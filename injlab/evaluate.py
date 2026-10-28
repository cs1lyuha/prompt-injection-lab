"""Evaluarea: rata de succes a atacurilor (ASR) și rata de alarme false, pe fiecare combinație de apărări.

    python -m injlab.evaluate          # tabele Markdown → results.md
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from injlab.agent import Defenses, run_case
from injlab.corpus import GOALS, OBFUSCATIONS, attacks, benign, held_out

CONFIGS = [
    Defenses(),
    Defenses(detect_raw=True),
    Defenses(detect_raw=True, normalize=True),
    Defenses(output_guard=True, tool_policy=True),
    Defenses(detect_raw=True, normalize=True, output_guard=True),
    Defenses(detect_raw=True, normalize=True, output_guard=True, tool_policy=True),
]


def asr(cases, d: Defenses) -> float:
    return sum(run_case(c, d).attack_succeeded for c in cases) / len(cases)


def breakdown(cases, d: Defenses, key) -> dict[str, float]:
    groups = defaultdict(list)
    for c in cases:
        groups[key(c)].append(run_case(c, d).attack_succeeded)
    return {k: sum(v) / len(v) for k, v in groups.items()}


def false_positives(d: Defenses) -> list[str]:
    return [c.id for c in benign() if run_case(c, d).flagged or "blocată" in run_case(c, d).response]


def report() -> str:
    tpl, held, ben = attacks(), held_out(), benign()
    lines = ["# Rezultate", "",
             f"{len(tpl)} atacuri din șabloane, {len(held)} atacuri parafrazate (set separat), {len(ben)} mesaje benigne.",
             "Model-țintă: worst-case (orice injecție care ajunge în context reușește).", "",
             "## Rata de succes a atacurilor (ASR) și alarme false", "",
             "| apărări | ASR șabloane | ASR parafraze | alarme false (benigne) |", "|---|---:|---:|---:|"]
    for d in CONFIGS:
        fp = false_positives(d)
        lines.append(f"| {d.name} | {asr(tpl, d):.1%} | {asr(held, d):.1%} | {len(fp)}/{len(ben)} |")

    full = CONFIGS[-1]
    lines += ["", f"## ASR pe obiective, cu toate apărările ({full.name})", "",
              "| obiectiv | șabloane | parafraze |", "|---|---:|---:|"]
    t, h = breakdown(tpl, full, lambda c: c.goal), breakdown(held, full, lambda c: c.goal)
    for g in GOALS:
        lines.append(f"| {g} | {t[g]:.0%} | {h[g]:.0%} |")

    l1 = Defenses(detect_raw=True)
    l12 = Defenses(detect_raw=True, normalize=True)
    lines += ["", "## Detecția pe tipuri de ofuscare (doar L1 vs. L1+L2, atacuri din șabloane)", "",
              "| ofuscare | ASR cu L1 | ASR cu L1+L2 |", "|---|---:|---:|"]
    a, b = breakdown(tpl, l1, lambda c: c.obfuscation), breakdown(tpl, l12, lambda c: c.obfuscation)
    for o in OBFUSCATIONS:
        lines.append(f"| {o} | {a[o]:.0%} | {b[o]:.0%} |")

    fp = false_positives(full)
    if fp:
        texts = {c.id: c.text for c in ben}
        lines += ["", "## Alarme false", ""] + [f"- `{i}`: „{texts[i]}”" for i in fp]
    return "\n".join(lines) + "\n"


def main() -> None:
    text = report()
    (Path(__file__).resolve().parent.parent / "results.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
