"""Every question the classifier asks, and the rules that turn the answers
into an action. Edit wording and thresholds here; bot.py only sends the
questions and acts on the verdict.

Each question is one yes/no judgment (a Noul) about the state built in
bot.build_state. The model never decides "spam or not": the rules in
`decide` do, so every verdict can be traced to the answers behind it."""

from dataclasses import dataclass, field

YES = 0.7  # an answer at or above this reads as yes
NO = 0.3  # below this reads as no; in between the state does not settle the question


@dataclass(frozen=True)
class Q:
    label: str  # shown to admins in reports
    instructions: str
    true: str
    false: str

    def payload(self) -> dict:
        return {"type": "noul", "instructions": self.instructions,
                "criteria": {"true": self.true, "false": self.false}}


# Asked about every message.
TEXT_QUESTIONS = {
    "easy_money": Q(
        "заработок / крипта / ставки",
        "Does `message` offer easy or fast earnings, crypto, investment, trading or betting opportunities?",
        # Describe situations, not sample phrases: example spam phrases here pulled Clef toward "yes"
        # on ordinary comments (0.5-0.7 on "@olga пойдём?"), while this wording keeps them under 0.2.
        "The message offers readers a way to make money or to invest, trade or bet.",
        "The message is conversation, a question or an answer, with no offer to readers.",
    ),
    "adult": Q(
        "18+ / знакомства",
        "Does `message` offer sexual content, escort services or dating?",
        "For example: links to explicit content, 'lonely girls nearby', an offer to meet up for a date.",
        "The message is ordinary conversation, including jokes or rude language.",
    ),
    "phishing": Q(
        "фишинг",
        "Does `message` ask readers to claim a prize, payment or giveaway, or to log in somewhere via a link?",
        "For example: 'you won, collect your reward here', 'confirm your account at this link', "
        "'get free Telegram Premium'.",
        "The message shares a link as a source, a map location or an answer to a question.",
    ),
    "self_promo": Q(
        "самопиар",
        "Does the author advertise their own product, service, business, course or channel in `message`?",
        "For example: 'I do manicures at home, prices in my profile', 'subscribe to my channel about Spain'.",
        "The author recommends someone else's business, answers a question with a link, or mentions their "
        "own job without offering it.",
    ),
    "lure_private": Q(
        "зовёт в ЛС / в канал",
        "Does `message` invite readers to contact the author privately or to join a channel, group or bot?",
        "For example: 'write me in DM', 'details in my profile', 'join our chat @...', 'start the bot'.",
        "The message asks or answers something in the discussion itself.",
    ),
    "generic": Q(
        "общий комментарий",
        "Could `message.text` be posted unchanged under almost any post in this channel?",
        "The comment is praise, agreement or a restatement, such as 'Very useful post, thank you! "
        "Barcelona really is amazing', with no detail tied to a specific post.",
        "The comment asks a specific question, shares a personal experience, disagrees, or mentions a detail "
        "that only fits one post.",
    ),
    "profile_promo": Q(
        "реклама в профиле",
        "Does `author.name`, `author.bio` or `author.personal_channel` advertise services, courses, "
        "a business or a channel?",
        "For example: a name like 'Anna | Nails Barcelona', a bio with prices or 'DM for consultation', "
        "a personal channel about earning money or the author's business.",
        "The profile shows only a personal name, a personal description, or a channel about the author's life.",
    ),
}

# Asked only when the message replies to a post or comment.
ON_TOPIC = Q(
    "по теме",
    "Is `message.text` about the subject of `replying_to.text`?",
    "The comment reacts to, asks about or adds to what `replying_to.text` discusses.",
    "The comment is about something `replying_to.text` does not discuss.",
)

# Asked only when an image could be attached.
IMAGE_QUESTIONS = {
    "image_scam": Q(
        "картинка: заработок / казино / 18+",
        "Does the image in `message.image` promote earnings, crypto, casinos, betting or adult content?",
        "For example: screenshots of payouts, a casino banner, explicit photos.",
        "An ordinary photo, a meme, or a screenshot related to the discussion.",
    ),
    "image_ad": Q(
        "картинка: реклама",
        "Is the image in `message.image` an advertisement for a product, service or channel?",
        "For example: a flyer with prices, a banner with a contact handle, phone number or QR code.",
        "An ordinary photo, a meme, or a screenshot related to the discussion.",
    ),
}

SCAM = ("easy_money", "adult", "phishing", "image_scam")
PROMO = ("self_promo", "lure_private", "image_ad")
NEURO = ("generic", "profile_promo")


# Questions about `message.text` itself; skipped for a picture without a caption.
NEEDS_TEXT = ("generic", "on_topic")


def build_questions(has_text: bool, has_reply: bool, has_image: bool) -> dict[str, Q]:
    qs = {k: q for k, q in TEXT_QUESTIONS.items() if has_text or k not in NEEDS_TEXT}
    if has_text and has_reply:
        qs["on_topic"] = ON_TOPIC
    if has_image:
        qs.update(IMAGE_QUESTIONS)
    return qs


@dataclass
class Verdict:
    action: str  # "ban", "delete", "review" (report only) or "pass"
    reason: str  # shown to admins
    fired: list[str] = field(default_factory=list)  # question ids that drove the verdict


def decide(a: dict[str, float]) -> Verdict:
    """The truth table. `a` maps question id to the Noul answer; questions
    that were not asked are absent."""
    yes = lambda q: a.get(q, 0.0) >= YES
    unsure = lambda q: NO <= a.get(q, 0.0) < YES

    scam = [q for q in SCAM if yes(q)]
    promo = [q for q in PROMO if yes(q)]
    lure = yes("lure_private")
    # A comment that replies to nothing has no topic to be on.
    on_topic = a.get("on_topic", 0.0)

    if yes("phishing"):  # no innocent reading
        return Verdict("ban", "Удалено и забанено: фишинг", ["phishing"])
    if scam and lure:
        return Verdict("ban", "Удалено и забанено: мошенничество + зовёт в ЛС/канал", scam + ["lure_private"])
    if scam:
        return Verdict("delete", "Удалено, похоже на спам", scam)
    if promo and on_topic < NO:
        return Verdict("delete", "Удалено: реклама не по теме", promo)
    if yes("generic") and yes("profile_promo"):
        return Verdict("delete", "Удалено, похоже на нейрокомментинг (реклама в профиле)", list(NEURO))
    if promo:
        return Verdict("review", "Проверьте: реклама, но, возможно, по теме", promo + ["on_topic"])
    unsure_scam = [q for q in SCAM if unsure(q)]
    if unsure_scam:
        return Verdict("review", "Проверьте: возможно, спам", unsure_scam)
    unsure_promo = [q for q in PROMO if unsure(q)]
    if unsure_promo and on_topic < NO:
        return Verdict("review", "Проверьте: возможно, реклама не по теме", unsure_promo)
    if all(a.get(q, 0.0) >= NO for q in NEURO) and any(unsure(q) for q in NEURO):
        return Verdict("review", "Проверьте: возможно, нейрокомментинг", list(NEURO))
    return Verdict("pass", "")


def label(qid: str) -> str:
    return ({**TEXT_QUESTIONS, **IMAGE_QUESTIONS, "on_topic": ON_TOPIC})[qid].label
