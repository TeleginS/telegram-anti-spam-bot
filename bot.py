"""Telegram anti-spam bot: messages from untrusted members are scored by
Cloudflare Clef-flash; while Clef is rate-limited or out of quota (or fails),
TypeSafe Jev scores them instead. The spam probability decides whether to
delete the message and ban the author."""

import asyncio
import base64
import html
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass

import httpx
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

env = os.environ
BOT_TOKEN = env.get("BOT_TOKEN", "")
CF_ACCOUNT_ID = env.get("CF_ACCOUNT_ID", "")
CF_API_TOKEN = env.get("CF_API_TOKEN", "")
TYPESAFE_API_KEY = env.get("TYPESAFE_API_KEY", "")
JEV_MODEL = env.get("JEV_MODEL", "jev-latest")
CAS_API_KEY = env.get("CAS_API_KEY", "")  # Combot API key; CAS rejects requests without one
ADMIN_IDS = {int(x) for x in env.get("ADMIN_IDS", "").replace(" ", "").split(",") if x}
GROUP_DESCRIPTION = env.get("GROUP_DESCRIPTION", "")
BAN_AT = float(env.get("BAN_THRESHOLD", "0.9"))
DELETE_AT = float(env.get("DELETE_THRESHOLD", "0.7"))
TRUST_AFTER = int(env.get("TRUST_AFTER", "3"))
DRY_RUN = env.get("DRY_RUN", "true").lower() in ("1", "true", "yes")
DB_PATH = env.get("DB_PATH", "/data/antispam.db")
POST_RULES = env.get("POST_RULES", "true").lower() in ("1", "true", "yes")
RULES_PATH = env.get("RULES_PATH", "/app/rules.txt")

CLEF_URL = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/run/@cf/cloudflare/clef-flash"
JEV_URL = "https://api.typesafe.ai/v1/systemone"

SPAM_QUESTION = {
    "is_spam": {
        "type": "noul",
        "instructions": (
            "The `state` is a message posted in a Telegram group chat by a member who is not yet trusted. "
            "Is this message spam? Spam includes: unsolicited advertising or self-promotion unrelated to the chat; "
            "crypto, investment, betting or 'easy money' offers; suspicious job offers (remote work, high pay, "
            "'write me in DM'); invitations to private messages, other channels or bots; adult or dating content; "
            "phishing or scam links; mass-forwarded promotional posts. Not spam: ordinary conversation, questions, "
            "opinions (even rude or off-topic), and links relevant to the discussion. "
            "`author.bio` and `author.personal_channel` come from the author's Telegram profile. "
            "If `message.image` is present, judge the attached image together with the text: an image is spam when "
            "it advertises earnings, crypto, casinos or betting, adult content, or shows contact handles, phone "
            "numbers or QR codes to lure people elsewhere. Ordinary photos, memes and screenshots relevant to the "
            "chat are not spam."
        ),
    }
}

# Asked only of Jev: Clef scores these comments far too low to act on.
NEURO_QUESTION = {
    "is_neurocomment": {
        "type": "noul",
        "instructions": (
            "The `state` is a comment in a Telegram channel discussion group. Is it 'neurocommenting'? That is a "
            "generic, AI-written comment (smooth, emotional, restates or praises the post, no concrete personal "
            "experience or question) posted by an account that promotes itself: its name, bio or personal channel "
            "advertises services, teaching, courses, a business or a channel. Neurocommenting is used to get readers "
            "to open the profile, so it is spam even when the text itself is on topic and polite. Answer no for "
            "comments that share real personal experience, ask something specific or argue, or when the profile "
            "advertises nothing."
        ),
    }
}
NEURO_SOURCE = "jev-neuro"

IMAGE_PLACEHOLDER ="__ATTACHED_IMAGE__"  # replaced per model: Clef shows images before the state, Jev by reference
CLEF_MIMES = ("image/jpeg", "image/png", "image/webp")
JEV_FORMATS = {"image/jpeg": "jpg", "image/png": "png"}


@dataclass
class Image:
    data: bytes
    mime: str
    width: int = 0  # 0 when Telegram does not report the size (image sent as a file)
    height: int = 0

    def fits_jev(self) -> bool:
        # Jev needs PNG/JPEG with each side within 280..1568 px.
        return self.mime in JEV_FORMATS and 280 <= min(self.width, self.height) and max(self.width, self.height) <= 1568

log = logging.getLogger("antispam")
router = Router()
http: httpx.AsyncClient
db: sqlite3.Connection
admin_cache: dict[int, tuple[float, set[int]]] = {}
cas_cache: dict[int, bool] = {}
profile_cache: dict[int, tuple[float, dict]] = {}  # user_id -> (time, bio and personal channel)
clef_paused_until = 0.0  # set when Clef reports a rate limit or exhausted quota
rules_posted_albums: dict[str, float] = {}  # media_group_id -> time, so an album gets one rules comment


# --- storage -----------------------------------------------------------------

def open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS members (
            chat_id INTEGER, user_id INTEGER,
            clean_count INTEGER DEFAULT 0, trusted INTEGER DEFAULT 0,
            PRIMARY KEY (chat_id, user_id));
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY, ts INTEGER, chat_id INTEGER, user_id INTEGER,
            text TEXT, p_clef REAL, p_jev REAL, action TEXT);
        """
    )
    return conn


def member(chat_id: int, user_id: int) -> tuple[int, bool]:
    row = db.execute(
        "SELECT clean_count, trusted FROM members WHERE chat_id=? AND user_id=?", (chat_id, user_id)
    ).fetchone()
    return (row[0], bool(row[1])) if row else (0, False)


def count_clean(chat_id: int, user_id: int) -> None:
    db.execute(
        "INSERT INTO members (chat_id, user_id, clean_count) VALUES (?, ?, 1) "
        "ON CONFLICT DO UPDATE SET clean_count = clean_count + 1, trusted = (clean_count + 1 >= ?)",
        (chat_id, user_id, TRUST_AFTER),
    )
    db.commit()


def set_trusted(chat_id: int, user_id: int) -> None:
    db.execute(
        "INSERT INTO members (chat_id, user_id, trusted) VALUES (?, ?, 1) ON CONFLICT DO UPDATE SET trusted = 1",
        (chat_id, user_id),
    )
    db.commit()


def record(chat_id, user_id, text, p_clef, p_jev, action) -> None:
    db.execute(
        "INSERT INTO actions (ts, chat_id, user_id, text, p_clef, p_jev, action) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (int(time.time()), chat_id, user_id, text[:2000], p_clef, p_jev, action),
    )
    db.commit()


# --- classifiers -------------------------------------------------------------

def extract_probability(data: dict, question: str = "is_spam") -> float:
    data = data.get("result", data)  # Cloudflare wraps the payload in {"result": ..., "success": ...}
    answer = data["answers"][question]
    if isinstance(answer, (int, float)):
        return float(answer)
    for key in ("noul", "probability", "p", "yes", "value"):
        if isinstance(answer.get(key), (int, float)):
            return float(answer[key])
    raise ValueError(f"unexpected answer shape: {answer!r}")


async def ask_clef(state: str, image: Image | None = None) -> dict:
    body = {"model": "clef-flash", "questions": SPAM_QUESTION}
    if image and image.mime in CLEF_MIMES:
        body["images"] = [f"data:{image.mime};base64,{base64.b64encode(image.data).decode()}"]
        body["state"] = state.replace(IMAGE_PLACEHOLDER, "attached image (shown before the state)")
    else:
        body["state"] = state.replace(IMAGE_PLACEHOLDER, "image attached but not available for review")
    r = await http.post(CLEF_URL, headers={"Authorization": f"Bearer {CF_API_TOKEN}"}, json=body)
    r.raise_for_status()
    return r.json()


async def ask_jev(state: str, image: Image | None = None, questions: dict = SPAM_QUESTION) -> dict:
    headers = {"Authorization": f"Bearer {TYPESAFE_API_KEY}"}
    body = {"model": JEV_MODEL, "questions": questions}
    if image and image.fits_jev():
        ref = f"img-{uuid.uuid4()}"  # unique, so the reference cannot match other text in the state
        body["state"] = state.replace(IMAGE_PLACEHOLDER, ref)
        body["assets"] = {ref: {"type": "image", "format": JEV_FORMATS[image.mime],
                                "data_base64": base64.b64encode(image.data).decode()}}
        headers["TypeSafe-Danger-Zone-Images"] = "true"  # image input is opt-in on TypeSafe
    else:
        body["state"] = state.replace(IMAGE_PLACEHOLDER, "image attached but not available for review")
    r = await http.post(JEV_URL, headers=headers, json=body)
    r.raise_for_status()
    return r.json()


def pause_clef(response: httpx.Response) -> None:
    """Skip Clef until its limit resets: the next UTC midnight for the daily
    allocation, otherwise Retry-After (or a minute) for a plain rate limit."""
    global clef_paused_until
    now = time.time()
    if "daily" in response.text.lower() or "allocation" in response.text.lower():
        clef_paused_until = (now // 86400 + 1) * 86400
    else:
        retry_after = response.headers.get("retry-after", "")
        clef_paused_until = now + (int(retry_after) if retry_after.isdigit() else 60)
    log.warning("clef-flash limit reached, using jev until %s UTC: %s",
                time.strftime("%Y-%m-%d %H:%M", time.gmtime(clef_paused_until)), response.text[:300])


async def classify(state: str, image: Image | None = None) -> tuple[float, str] | None:
    """Spam probability and the model that produced it; None if both failed."""
    if time.time() >= clef_paused_until:
        try:
            return extract_probability(await ask_clef(state, image)), "clef-flash"
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                pause_clef(e.response)
            else:
                log.warning("clef-flash failed, falling back to jev: %s %s", e, e.response.text[:300])
        except Exception as e:  # timeouts, malformed answers: still fall back
            log.warning("clef-flash failed, falling back to jev: %s", e)
    try:
        return extract_probability(await ask_jev(state, image)), "jev"
    except Exception as e:
        body = getattr(getattr(e, "response", None), "text", "")
        log.warning("jev failed: %s %s", e, body[:300])
        return None


async def classify_neurocomment(state: str) -> float | None:
    """Probability that the message is neurocommenting; None if Jev failed."""
    try:
        return extract_probability(await ask_jev(state, questions=NEURO_QUESTION), "is_neurocomment")
    except Exception as e:
        body = getattr(getattr(e, "response", None), "text", "")
        log.warning("jev neurocomment check failed: %s %s", e, body[:300])
        return None


async def in_cas(user_id: int) -> bool:
    """Combot Anti-Spam: a public list of known spam accounts."""
    if not CAS_API_KEY:
        return False
    if user_id not in cas_cache:
        try:
            r = await http.get("https://api.cas.chat/check", params={"user_id": user_id},
                               headers={"Authorization": f"Bearer {CAS_API_KEY}"}, timeout=5)
            data = r.json()
            if r.status_code != 200 or data.get("error_code"):  # an API error is not a verdict, do not cache it
                log.warning("CAS check failed: %s %s", r.status_code, r.text[:200])
                return False
            cas_cache[user_id] = bool(data.get("ok"))
        except Exception as e:
            log.warning("CAS check failed: %s", e)
            return False
    return cas_cache[user_id]


# --- telegram ----------------------------------------------------------------

async def is_admin(bot: Bot, chat_id: int, user_id: int) -> bool:
    ts, ids = admin_cache.get(chat_id, (0.0, set()))
    if time.time() - ts > 600:
        ids = {m.user.id for m in await bot.get_chat_administrators(chat_id)}
        admin_cache[chat_id] = (time.time(), ids)
    return user_id in ids


async def fetch_profile(bot: Bot, user_id: int) -> dict:
    """The author's bio and personal channel: neurocommenting accounts advertise
    there, not in the comment itself. Cached for an hour; empty on failure."""
    ts, profile = profile_cache.get(user_id, (0.0, {}))
    if time.time() - ts < 3600:
        return profile
    try:
        info = await bot.get_chat(user_id)
        channel = info.personal_chat
        profile = {
            "bio": info.bio,
            "personal_channel": {"title": channel.title, "username": channel.username} if channel else None,
        }
    except Exception as e:  # e.g. "chat not found" for users the bot cannot see; not retried within the hour
        log.warning("cannot fetch profile of user %s: %s", user_id, e)
        profile = {}
    profile_cache[user_id] = (time.time(), profile)
    return profile


async def fetch_image(bot: Bot, msg: Message) -> Image | None:
    """The picture to classify: a photo, an image sent as a file, or the
    preview frame of a video or GIF."""
    try:
        if msg.photo:
            # Telegram lists sizes smallest first; take the largest one Jev also accepts.
            fitting = [p for p in msg.photo if max(p.width, p.height) <= 1568]
            item = (fitting or msg.photo[:1])[-1]
            mime, width, height = "image/jpeg", item.width, item.height
        elif msg.document and msg.document.mime_type in CLEF_MIMES and (msg.document.file_size or 0) <= 4 << 20:
            item, mime, width, height = msg.document, msg.document.mime_type, 0, 0
        else:
            media = msg.video or msg.animation
            item = media.thumbnail if media else None
            if item is None:
                return None
            mime, width, height = "image/jpeg", item.width, item.height
        buf = await bot.download(item.file_id)
        return Image(buf.read(), mime, width, height)
    except Exception as e:
        log.warning("cannot download image from msg %s: %s", msg.message_id, e)
        return None


def build_state(msg: Message, clean_count: int, edited: bool, image: Image | None = None,
                profile: dict | None = None) -> str:
    text = msg.text or msg.caption or ""
    entities = (msg.entities or []) + (msg.caption_entities or [])
    links = [e.url or e.extract_from(text) for e in entities if e.type in ("url", "text_link")]
    mentions = [e.extract_from(text) for e in entities if e.type == "mention"]
    u = msg.from_user
    forwarded = None
    if msg.forward_origin:
        origin = msg.forward_origin
        chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
        forwarded = chat.title if chat else origin.type
    state = {
        "platform": "Telegram group chat",
        "group_title": msg.chat.title,
        "group_description": GROUP_DESCRIPTION or None,
        "author": {
            "name": u.full_name,
            "username": u.username,
            "is_premium": bool(u.is_premium),
            "bio": (profile or {}).get("bio"),
            "personal_channel": (profile or {}).get("personal_channel"),
            "earlier_clean_messages_in_group": clean_count,
        },
        "message": {
            "text": text[:4000],
            "links": links,
            "mentions": mentions,
            "forwarded_from": forwarded,
            "has_media": bool(msg.photo or msg.video or msg.document or msg.animation),
            "image": IMAGE_PLACEHOLDER if image else None,
            "has_inline_buttons": bool(msg.reply_markup),
            "is_edit_of_earlier_message": edited,
        },
    }
    return json.dumps(state, ensure_ascii=False)


async def report(bot: Bot, msg: Message, p: float, source: str, verdict: str, buttons: list[tuple[str, str]],
                 has_image: bool = False) -> None:
    u = msg.from_user
    who = f'<a href="tg://user?id={u.id}">{html.escape(u.full_name)}</a>'
    if u.username:
        who += f" @{html.escape(u.username)}"
    text = (
        f"{'🧪 ТЕСТ: ' if DRY_RUN else ''}<b>{verdict}</b>\n"
        f"Чат: {html.escape(msg.chat.title or str(msg.chat.id))}\n"
        f"Автор: {who} (<code>{u.id}</code>)\n"
        f"Вероятность спама: {p:.0%} ({source})\n\n"
        + ("🖼 С картинкой\n" if has_image else "")
        + f"<blockquote>{html.escape((msg.text or msg.caption or '[без текста]')[:800])}</blockquote>"
    )
    kb = InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t, callback_data=f"{a}:{msg.chat.id}:{u.id}") for t, a in buttons]]
    )
    for admin in ADMIN_IDS:
        try:
            await bot.send_message(admin, text, reply_markup=kb, disable_web_page_preview=True)
        except Exception as e:
            log.warning("cannot notify admin %s (did they /start the bot?): %s", admin, e)


async def moderate(msg: Message, bot: Bot, edited: bool) -> None:
    u = msg.from_user

    def skip(reason: str) -> None:
        log.info("skip chat=%s msg=%s user=%s: %s", msg.chat.id, msg.message_id, u.id if u else None, reason)

    if msg.sender_chat:
        return skip("sent on behalf of a chat (anonymous admin or channel)")
    if not u or u.is_bot or msg.is_automatic_forward:
        return skip("bot or automatic forward")
    if await is_admin(bot, msg.chat.id, u.id):
        return skip("group admin")
    clean_count, trusted = member(msg.chat.id, u.id)
    if trusted:
        return skip("trusted member")
    text = msg.text or msg.caption or ""
    has_visual = bool(msg.photo or msg.video or msg.animation or
                      (msg.document and msg.document.mime_type in CLEF_MIMES))
    if not text and not msg.forward_origin and not has_visual:
        return skip("nothing to classify (service message, sticker, voice or file)")

    image = None
    if await in_cas(u.id):
        p, source = 1.0, "CAS"
    else:
        image = await fetch_image(bot, msg) if has_visual else None
        profile = await fetch_profile(bot, u.id)
        state = build_state(msg, clean_count, edited, image, profile)
        result = await classify(state, image)
        if result is None:
            log.error("both classifiers failed; message %s in %s left untouched", msg.message_id, msg.chat.id)
            return
        p, source = result
        # Neurocomments look clean on their own; the advertising sits in the profile.
        if p < DELETE_AT and text and (profile.get("bio") or profile.get("personal_channel")):
            p_neuro = await classify_neurocomment(state)
            log.info("neurocomment check: chat=%s msg=%s user=%s p=%s", msg.chat.id, msg.message_id, u.id, p_neuro)
            if p_neuro is not None and p_neuro > p:
                p, source = p_neuro, NEURO_SOURCE

    log.info("chat=%s msg=%s user=%s p=%.2f source=%s edited=%s image=%s",
             msg.chat.id, msg.message_id, u.id, p, source, edited, image.mime if image else None)

    # A neurocomment verdict rests on the profile, so it only deletes and leaves the ban to an admin.
    if p >= BAN_AT and source != NEURO_SOURCE:
        action = "ban"
        if not DRY_RUN:
            await bot.delete_message(msg.chat.id, msg.message_id)
            await bot.ban_chat_member(msg.chat.id, u.id, revoke_messages=True)
        verdict = "Удалено и забанено" + (" (в базе CAS)" if source == "CAS" else "")
        await report(bot, msg, p, source, verdict, [("↩️ Разбанить", "unban")], has_image=bool(image))
    elif p >= DELETE_AT:
        action = "delete"
        if not DRY_RUN:
            await bot.delete_message(msg.chat.id, msg.message_id)
        verdict = "Удалено, похоже на нейрокомментинг (реклама в профиле)" if source == NEURO_SOURCE \
            else "Удалено, похоже на спам"
        await report(bot, msg, p, source, verdict, [("🔨 Забанить", "ban"), ("✅ Не спам", "trust")],
                     has_image=bool(image))
    else:
        action = "pass"
        if not edited:
            count_clean(msg.chat.id, u.id)
    p_clef = p if source == "clef-flash" else None
    p_jev = p if source in ("jev", NEURO_SOURCE) else None
    record(msg.chat.id, u.id, text or ("[картинка]" if image else ""), p_clef, p_jev,
           action + (" (dry-run)" if DRY_RUN and action != "pass" else ""))


@router.message(F.is_automatic_forward, F.chat.type == "supergroup")
async def on_channel_post(msg: Message) -> None:
    """A new channel post landed in the linked discussion group: reply with the
    rules so they become the first comment. Edits arrive as edited_message and
    never reach this handler."""
    if not POST_RULES:
        return
    if msg.media_group_id:
        now = time.time()
        for album, ts in list(rules_posted_albums.items()):
            if now - ts > 3600:
                del rules_posted_albums[album]
        if msg.media_group_id in rules_posted_albums:
            return
        rules_posted_albums[msg.media_group_id] = now
    try:
        with open(RULES_PATH, encoding="utf-8") as f:
            rules = f.read().strip()
    except OSError as e:
        log.warning("rules file unavailable: %s", e)
        return
    if not rules:
        return
    await msg.reply(rules, disable_notification=True, disable_web_page_preview=True)
    log.info("rules posted under channel post: chat=%s msg=%s", msg.chat.id, msg.message_id)


@router.message(F.chat.type.in_({"group", "supergroup"}))
async def on_message(msg: Message, bot: Bot) -> None:
    await moderate(msg, bot, edited=False)


@router.edited_message(F.chat.type.in_({"group", "supergroup"}))
async def on_edit(msg: Message, bot: Bot) -> None:
    await moderate(msg, bot, edited=True)


@router.message(Command("start", "whoami"), F.chat.type == "private")
async def whoami(msg: Message) -> None:
    role = "администратор бота" if msg.from_user.id in ADMIN_IDS else "не администратор бота"
    await msg.answer(f"Ваш Telegram ID: <code>{msg.from_user.id}</code> ({role}).")


@router.message(F.chat.type == "private", F.photo | F.video | F.animation | F.document)
async def check_media(msg: Message, bot: Bot) -> None:
    """Admins test image classification by sending the bot a picture (caption optional)."""
    if msg.from_user.id not in ADMIN_IDS:
        return
    image = await fetch_image(bot, msg)
    if image is None:
        await msg.answer("Не удалось взять картинку: поддерживаются фото, картинки JPEG/PNG/WebP и превью видео или GIF.")
        return
    caption = (msg.caption or "").removeprefix("/check").strip()
    state = json.dumps({"platform": "Telegram group chat", "group_description": GROUP_DESCRIPTION or None,
                        "message": {"text": caption, "image": IMAGE_PLACEHOLDER}}, ensure_ascii=False)
    result = await classify(state, image)
    if result is None:
        await msg.answer("Обе модели не ответили, подробности в логах.")
        return
    p, source = result
    verdict = "бан" if p >= BAN_AT else "удаление" if p >= DELETE_AT else "пропуск"
    await msg.answer(f"Вероятность спама: <b>{p:.0%}</b> ({source})\nРешение: {verdict}")


@router.message(Command("check"), F.chat.type == "private")
async def check(msg: Message) -> None:
    """Admins test the classifier: /check <text>."""
    if msg.from_user.id not in ADMIN_IDS:
        return
    text = (msg.text or "").partition(" ")[2].strip()
    if not text:
        await msg.answer("Напишите текст после команды: <code>/check текст сообщения</code>")
        return
    state = json.dumps({"platform": "Telegram group chat", "group_description": GROUP_DESCRIPTION or None,
                        "message": {"text": text[:4000]}}, ensure_ascii=False)
    result = await classify(state)
    if result is None:
        await msg.answer("Обе модели не ответили, подробности в логах.")
        return
    p, source = result
    verdict = "бан" if p >= BAN_AT else "удаление" if p >= DELETE_AT else "пропуск"
    await msg.answer(f"Вероятность спама: <b>{p:.0%}</b> ({source})\nРешение: {verdict}")


@router.message(Command("stats"), F.chat.type == "private")
async def stats(msg: Message) -> None:
    if msg.from_user.id not in ADMIN_IDS:
        return
    since = int(time.time()) - 86400
    rows = db.execute("SELECT action, COUNT(*) FROM actions WHERE ts > ? GROUP BY action", (since,)).fetchall()
    lines = [f"{a}: {n}" for a, n in rows] or ["нет событий"]
    mode = "тестовый (ничего не удаляю)" if DRY_RUN else "боевой"
    await msg.answer(f"Режим: {mode}\nЗа 24 часа:\n" + "\n".join(lines))


@router.callback_query(F.data.regexp(r"^(unban|ban|trust):-?\d+:\d+$"))
async def on_button(cb: CallbackQuery, bot: Bot) -> None:
    if cb.from_user.id not in ADMIN_IDS:
        await cb.answer("Нет прав", show_alert=True)
        return
    action, chat_id, user_id = cb.data.split(":")
    chat_id, user_id = int(chat_id), int(user_id)
    if action == "unban":
        await bot.unban_chat_member(chat_id, user_id, only_if_banned=True)
        set_trusted(chat_id, user_id)
        note = "↩️ Разбанен и добавлен в доверенные"
    elif action == "ban":
        await bot.ban_chat_member(chat_id, user_id, revoke_messages=True)
        note = "🔨 Забанен"
    else:
        set_trusted(chat_id, user_id)
        note = "✅ Отмечен как не спамер"
    await cb.message.edit_text(cb.message.html_text + f"\n\n<b>{note}</b> — {html.escape(cb.from_user.full_name)}")
    await cb.answer()


async def selftest(text: str, image_path: str | None = None) -> None:
    """Classify one sample message normally, then again with Clef answering
    429 out-of-quota, to check the fallback to Jev. An optional PNG/JPEG file
    is attached to the message."""
    global ask_clef
    image = None
    message = {"text": text}
    if image_path:
        with open(image_path, "rb") as f:
            data = f.read()
        mime = "image/png" if data[:4] == b"\x89PNG" else "image/jpeg"
        width, height = map(int, sys.argv[4].split("x")) if len(sys.argv) > 4 else (0, 0)
        image = Image(data, mime, width, height)
        message["image"] = IMAGE_PLACEHOLDER
        print(f"image: {mime} {width}x{height} {len(data)} bytes, jev accepts: {image.fits_jev()}")
    state = json.dumps({"platform": "Telegram group chat", "message": message}, ensure_ascii=False)
    print("normal:", await classify(state, image))

    async def exhausted_clef(_state: str, _image: Image | None = None) -> dict:
        request = httpx.Request("POST", CLEF_URL)
        body = {"errors": [{"code": 4006, "message": "you have used up your daily free allocation of 10,000 neurons"}]}
        raise httpx.HTTPStatusError("429", request=request, response=httpx.Response(429, json=body, request=request))

    real_clef, ask_clef = ask_clef, exhausted_clef
    print("clef out of quota:", await classify(state, image))
    ask_clef = real_clef
    print("while paused:", await classify(state, image), "| clef paused until",
          time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(clef_paused_until)))


async def main() -> None:
    global http, db
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    http = httpx.AsyncClient(timeout=15)
    if len(sys.argv) > 2 and sys.argv[1] == "--selftest":
        await selftest(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
        return
    db = open_db()
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher()
    dp.include_router(router)
    log.info("starting: dry_run=%s ban_at=%s delete_at=%s trust_after=%s cas=%s admins=%s",
             DRY_RUN, BAN_AT, DELETE_AT, TRUST_AFTER, "on" if CAS_API_KEY else "off (no CAS_API_KEY)",
             sorted(ADMIN_IDS))
    await dp.start_polling(bot, allowed_updates=["message", "edited_message", "callback_query"])


if __name__ == "__main__":
    asyncio.run(main())
