"""Apărările, pe straturi. Fiecare se poate porni separat, ca să-i măsurăm efectul.

L1 `detect`: detector pe text brut (regex multilingve: ro / en / ru).
L2 `normalize` + `detect`: întâi „desfacem” ofuscările (homoglife chirilice, leet, litere
   spațiate, base64), apoi detectăm.
L3 `guard_output`: verificarea răspunsului: secretul (canary) nu are voie să iasă, iar
   linkurile și imaginile spre domenii din afara allowlist-ului sunt eliminate.
L4 `authorize_tool`: politica de unelte, în cod. O acțiune sensibilă trebuie cerută de
   utilizatorul de încredere, nu de textul dintr-un document.

L1 și L2 depind de cât de bine ghicim forma atacului. L3 și L4 nu depind de atac deloc,
de aceea sunt ultima linie.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

DETECTORS: list[tuple[str, re.Pattern[str]]] = [
    ("override", re.compile(
        r"\b(ignor\w*|disregard|forget|uit\w*|игнорир\w*|забудь)\b[^.\n]{0,40}"
        r"\b(instruc\w*|rules|regul\w*|tot|everything|инструкц\w*|правила|всё|все)\b", re.I)),
    ("system_prompt", re.compile(r"(system prompt|promptul de sistem|системн\w* промпт)", re.I)),
    ("fake_authority", re.compile(r"(new instruction|instrucțiune nouă|новая инструкция)\b.{0,30}"
                                  r"(admin|administrator|администратор)", re.I)),
    ("role_takeover", re.compile(r"(from now on|de acum|теперь)\b.{0,40}(only|doar|только)", re.I)),
    ("md_exfil", re.compile(r"!\[[^\]]*\]\(https?://", re.I)),
    ("decode_exec", re.compile(r"(decode and (run|execute)|decodează și execută|декодируй и выполни)", re.I)),
]

CYRILLIC_TO_LATIN = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "і": "i", "х": "x",
                                   "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X"})
LEET_TO_LATIN = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"})
B64_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}")


def detect(text: str) -> list[str]:
    return [name for name, pattern in DETECTORS if pattern.search(text)]


def _fix_word(word: str) -> str:
    letters = sum(c.isalpha() for c in word)
    # un cuvânt care amestecă litere latine cu chirilice e aproape sigur homoglifă
    has_latin = any("a" <= c.lower() <= "z" for c in word)
    has_cyr = any("Ѐ" <= c <= "ӿ" for c in word)
    if has_latin and has_cyr:
        word = word.translate(CYRILLIC_TO_LATIN)
    # leet doar în cuvinte care au și litere și cifre („1gn0ră”), nu în numere („9999”)
    digits = sum(c.isdigit() for c in word)
    if any(c.islower() for c in word) and 0 < digits <= letters and len(word) <= 20:
        word = word.translate(LEET_TO_LATIN)
    return word


SPACED = re.compile(r"(?<!\S)(?:\S {1,3}){2,}\S(?!\S)")


def _despace(m: re.Match[str]) -> str:
    # „N e w   i n s t r u c t i o n” → „New instruction”: un spațiu = în cuvânt, trei = între cuvinte
    return m.group(0).replace("   ", "\x00").replace(" ", "").replace("\x00", " ")


def _decode_b64(m: re.Match[str]) -> str:
    token = m.group(0)
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return token
    return decoded if sum(c.isprintable() for c in decoded) / max(1, len(decoded)) > 0.9 else token


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = B64_TOKEN.sub(_decode_b64, text)       # întâi base64: altfel „reparațiile” de mai jos strică tokenul
    text = SPACED.sub(_despace, text)
    return re.sub(r"\S+", lambda m: _fix_word(m.group(0)), text)


@dataclass
class OutputVerdict:
    text: str
    blocked: bool
    reasons: list[str]


URL = re.compile(r"(!?\[[^\]]*\])\((https?://[^)\s]+)\)|https?://[^\s)]+")


def guard_output(text: str, *, canary: str, allowed_domains: set[str]) -> OutputVerdict:
    reasons = []
    if canary in text or canary.lower() in text.lower():
        return OutputVerdict("Nu pot ajuta cu această cerere.", True, ["canary"])

    def strip_url(m: re.Match[str]) -> str:
        url = m.group(2) or m.group(0)
        domain = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        if domain in allowed_domains or any(domain.endswith("." + d) for d in allowed_domains):
            return m.group(0)
        reasons.append(f"url:{domain}")
        return "[link eliminat]"

    cleaned = URL.sub(strip_url, text)
    return OutputVerdict(cleaned, False, reasons)


SENSITIVE_TOOLS = {"refund"}
INTENT_WORDS = {"refund": re.compile(r"(refund|rambursa|înapoi banii|banii înapoi|возврат|верните деньги)", re.I)}


def authorize_tool(name: str, args: dict, *, user_message: str, user_role: str, order_total: float) -> tuple[bool, str]:
    """Politica e în cod: modelul poate *propune* orice, dar acțiunea trece doar dacă
    (1) utilizatorul de încredere a cerut-o el însuși, (2) are rolul potrivit, (3) argumentele sunt plauzibile."""
    if name not in SENSITIVE_TOOLS:
        return True, "ok"
    if not INTENT_WORDS[name].search(user_message):
        return False, "acțiunea nu a fost cerută de utilizator (vine din conținut neverificat)"
    if user_role not in {"support", "admin"}:
        return False, f"rolul {user_role} nu poate face {name}"
    if not 0 < float(args.get("amount", 0)) <= order_total:
        return False, "sumă în afara limitelor comenzii"
    return True, "ok"
