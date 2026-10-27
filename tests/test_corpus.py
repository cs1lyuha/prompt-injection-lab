import base64

from injlab.corpus import GOALS, OBFUSCATIONS, VECTORS, attacks, benign, held_out, obfuscate


def test_attack_grid_is_complete():
    a = attacks()
    assert len(a) == 3 * len(GOALS) * len(VECTORS) * len(OBFUSCATIONS) == 180
    assert len({c.id for c in a}) == len(a)


def test_obfuscations():
    assert obfuscate("Ignore all", "spaced").startswith("I g n o r e")
    assert "о" in obfuscate("Ignore", "homoglyph")  # „o” chirilic
    assert base64.b64decode(obfuscate("Ignore all", "base64").split(": ")[1]).decode() == "Ignore all"
    assert obfuscate("Ignore", "leet") == "Ign0r3"  # doar litere mici: „I” mare rămâne


def test_untrusted_vectors_hide_payload_inside_normal_content():
    doc = next(c for c in attacks() if c.vector == "document")
    assert doc.text.startswith("Politica de retur") and doc.user_message.startswith("Rezumă")


def test_benign_and_held_out_sets():
    assert len(benign()) == 30 and not any(c.attack for c in benign())
    h = held_out()
    assert len(h) == 32 and {c.goal for c in h} == set(GOALS)
