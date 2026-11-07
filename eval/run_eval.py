"""Run the cases in cases.py through the real questions and decision rules.

    docker compose run --rm -T -v ./eval:/eval -w /eval -e PYTHONPATH=/app antispam \
        python run_eval.py [jev|clef|both] [out.json]

Sends every case to the live API with the keys from .env: one Jev pass is
about 40k tokens, and Clef passes use its free daily quota. Prints one line
per case with the answers at or above 0.3, then the score on tuning and
holdout cases. With out.json, also saves each case's state and answers so a
result can be rerun (the directory must be writable by the container user)."""

import asyncio
import json
import sys

import httpx

import bot
from cases import CASES
from questions import decide


def state_for(c: dict) -> str:
    """The same shape as bot.build_state, built from a case instead of a Telegram message."""
    return json.dumps(bot.compact({
        "chat": bot.compact({"description": bot.GROUP_DESCRIPTION,
                             "kind": "comments under posts of a Telegram channel"}),
        "author": bot.compact(c["author"]),
        "replying_to": {"text": c["post"]} if c.get("post") else None,
        "message": bot.compact({"text": c["text"], "link_targets": c.get("link_targets")}),
    }), ensure_ascii=False)


async def run_one(model: str, c: dict) -> dict:
    state = state_for(c)
    ask = bot.ask_jev if model == "jev" else bot.ask_clef
    try:
        answers = await ask(state, None, True, bool(c.get("post")))
    except httpx.HTTPStatusError as e:
        return {"model": model, "id": c["id"], "error": f"{e.response.status_code} {e.response.text[:200]}"}
    except Exception as e:  # noqa: BLE001 - report and keep going
        return {"model": model, "id": c["id"], "error": repr(e)}
    v = decide(answers)
    return {"model": model, "id": c["id"], "holdout": c.get("holdout", False), "expect": c["expect"],
            "got": v.action, "fired": v.fired, "answers": answers, "state": state}


async def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "jev"
    out = sys.argv[2] if len(sys.argv) > 2 else None
    models = ["jev", "clef"] if which == "both" else [which]
    bot.http = httpx.AsyncClient(timeout=30)
    sem = asyncio.Semaphore(4)

    async def guarded(m, c):
        async with sem:
            return await run_one(m, c)

    results = await asyncio.gather(*(guarded(m, c) for m in models for c in CASES))
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=1)
    for m in models:
        rs = [r for r in results if r["model"] == m]
        print(f"\n=== {m}")
        for r in rs:
            if "error" in r:
                print(f"  ERR  {r['id']}: {r['error']}")
                continue
            mark = "ok " if r["got"] == r["expect"] else "XX "
            top = ", ".join(f"{k}={p:.2f}" for k, p in sorted(r["answers"].items(), key=lambda kv: -kv[1])
                            if p >= 0.3)
            print(f"  {mark}{'H ' if r['holdout'] else '  '}{r['id']:<24} "
                  f"expect={r['expect']:<6} got={r['got']:<6} [{top}]")
        for split in (False, True):
            s = [r for r in rs if "error" not in r and r["holdout"] == split]
            print(f"  {'holdout' if split else 'tuning '}: {sum(r['got'] == r['expect'] for r in s)}/{len(s)}")


if __name__ == "__main__":
    asyncio.run(main())
