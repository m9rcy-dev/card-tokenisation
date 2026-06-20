"""
Generates docs/card-tokenisation-overview.pptx
Run: python3 docs/build_slides.py
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.oxml.ns import qn
from lxml import etree

# ── Palette ──────────────────────────────────────────────────────────────────
NAVY    = RGBColor(0x0D, 0x1B, 0x3E)
TEAL    = RGBColor(0x00, 0x8C, 0x8C)
WHITE   = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT   = RGBColor(0xF0, 0xF4, 0xF8)
GRAY    = RGBColor(0x55, 0x65, 0x7A)
GREEN   = RGBColor(0x1A, 0x8C, 0x4E)
AMBER   = RGBColor(0xC8, 0x7F, 0x00)
PURPLE  = RGBColor(0x5A, 0x3A, 0x8C)
BLUE    = RGBColor(0x1A, 0x5C, 0x8C)
RED     = RGBColor(0x8C, 0x1A, 0x1A)
LGRAY   = RGBColor(0xD8, 0xE0, 0xEA)
STEEL   = RGBColor(0xB0, 0xC4, 0xDE)

W = Inches(13.33)
H = Inches(7.5)

prs = Presentation()
prs.slide_width  = W
prs.slide_height = H
blank = prs.slide_layouts[6]


# ── Helpers ──────────────────────────────────────────────────────────────────

def bg(slide, colour=NAVY):
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = colour

def box(slide, x, y, w, h, fill_colour, lines=None,
        font_size=14, bold=False, font_colour=WHITE,
        align=PP_ALIGN.CENTER, border_colour=None, border_pt=0):
    tf = slide.shapes.add_textbox(
        Inches(x), Inches(y), Inches(w), Inches(h))
    frame = tf.text_frame
    frame.word_wrap = True

    fill = tf.fill
    fill.solid()
    fill.fore_color.rgb = fill_colour

    if border_colour and border_pt:
        tf.line.color.rgb = border_colour
        tf.line.width = Pt(border_pt)

    if lines:
        if isinstance(lines, str):
            lines = [lines]
        for idx, line in enumerate(lines):
            p = frame.paragraphs[idx] if idx == 0 else frame.add_paragraph()
            p.alignment = align
            run = p.add_run()
            run.text = line
            run.font.size = Pt(font_size)
            run.font.bold = bold
            run.font.color.rgb = font_colour
    return tf

def label(slide, x, y, w, h, text, font_size=13, bold=False,
          colour=WHITE, align=PP_ALIGN.LEFT, wrap=True):
    tf = slide.shapes.add_textbox(
        Inches(x), Inches(y), Inches(w), Inches(h))
    frame = tf.text_frame
    frame.word_wrap = wrap
    p = frame.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(font_size)
    run.font.bold = bold
    run.font.color.rgb = colour
    return tf

def mlabel(slide, x, y, w, h, lines, font_size=13, bold=False,
           colour=WHITE, align=PP_ALIGN.LEFT, line_bold=None):
    """Multi-line label; line_bold is a list of bools, one per line."""
    tf = slide.shapes.add_textbox(
        Inches(x), Inches(y), Inches(w), Inches(h))
    frame = tf.text_frame
    frame.word_wrap = True
    for i, line in enumerate(lines):
        p = frame.paragraphs[i] if i == 0 else frame.add_paragraph()
        p.alignment = align
        run = p.add_run()
        run.text = line
        run.font.size = Pt(font_size)
        is_bold = (line_bold[i] if line_bold and i < len(line_bold) else bold)
        run.font.bold = is_bold
        run.font.color.rgb = colour
    return tf

def arrow_h(slide, x, y, length, colour=TEAL, width_pt=2.5):
    c = slide.shapes.add_connector(
        1, Inches(x), Inches(y), Inches(x + length), Inches(y))
    c.line.color.rgb = colour
    c.line.width = Pt(width_pt)
    return c

def arrow_v(slide, x, y, length, colour=TEAL, width_pt=2.5):
    c = slide.shapes.add_connector(
        1, Inches(x), Inches(y), Inches(x), Inches(y + length))
    c.line.color.rgb = colour
    c.line.width = Pt(width_pt)
    return c

def header(slide, title, subtitle=None, dark=True):
    box(slide, 0, 0, 13.33, 0.18, TEAL)
    tc = WHITE if dark else NAVY
    label(slide, 0.4, 0.28, 12.5, 0.55, title,
          font_size=26, bold=True, colour=tc if dark else NAVY)
    if subtitle:
        label(slide, 0.4, 0.85, 12.5, 0.38, subtitle,
              font_size=14, colour=STEEL if dark else GRAY)


# ════════════════════════════════════════════════════════════════════════════
# Slide 1 — Title
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, NAVY)
box(s, 0, 0, 13.33, 0.18, TEAL)
box(s, 0, 7.32, 13.33, 0.18, TEAL)

label(s, 1.2, 1.5, 11, 1.2,
      "Card Tokenisation System",
      font_size=50, bold=True, colour=WHITE, align=PP_ALIGN.CENTER)

label(s, 1.2, 2.8, 11, 0.6,
      "Keeping card numbers safe — without stopping payments",
      font_size=22, colour=STEEL, align=PP_ALIGN.CENTER)

label(s, 1.2, 3.7, 11, 0.5,
      "A plain-language guide to how we protect payment data",
      font_size=16, colour=GRAY, align=PP_ALIGN.CENTER)

label(s, 1.2, 6.9, 11, 0.35,
      "Confidential — Internal Use Only",
      font_size=12, colour=GRAY, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# Slide 2 — The Problem
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, LIGHT)
header(s, "The Problem: Every Copy of a Card Number Is a Risk", dark=False)

# Three columns
cols = [
    (RED,    "⚠  The Target",
     ["Real card numbers are stored",
      "across many systems —",
      "checkout, payments, CRM,",
      "analytics, logs.",
      "",
      "Every copy is a target.",
      "One breach exposes them all."]),
    (PURPLE, "💸  The Cost",
     ["A stolen card number can be",
      "used immediately for fraud.",
      "",
      "Average cost of a breach:",
      "millions in fines, fraud",
      "reimbursement, and reputation",
      "damage."]),
    (BLUE,   "📋  The Compliance Burden",
     ["PCI-DSS mandates strict security",
      "controls on every system that",
      "touches a card number.",
      "",
      "More copies = more systems",
      "in scope = more audits",
      "= more cost."]),
]
for i, (colour, title, lines) in enumerate(cols):
    x = 0.45 + i * 4.25
    box(s, x, 1.35, 4.0, 0.65, colour, title, font_size=15, bold=True,
        align=PP_ALIGN.CENTER)
    for j, line in enumerate(lines):
        label(s, x + 0.15, 2.1 + j * 0.33, 3.7, 0.35, line,
              font_size=13, colour=GRAY)

label(s, 0.4, 5.5, 12.5, 0.6,
      "The Solution: replace the real card number with a safe stand-in everywhere except the vault.",
      font_size=17, bold=True, colour=TEAL, align=PP_ALIGN.CENTER)

box(s, 0.5, 6.2, 5.7, 0.7, RED,
    "5412 7534 9823 1049  ← Real card (dangerous to store)", font_size=14)
label(s, 6.3, 6.32, 0.5, 0.5, "→", font_size=24, colour=TEAL, align=PP_ALIGN.CENTER)
box(s, 6.9, 6.2, 6.0, 0.7, GREEN,
    "3a4f9d2e-1b5c-4f8a-a3e7  ← Token (safe to store anywhere)", font_size=14)


# ════════════════════════════════════════════════════════════════════════════
# Slide 3 — Three Layers of Protection (mental model intro)
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, NAVY)
header(s, "Three Layers of Protection",
       "Before we see the flows — here is the mental model")

# Central nested-box diagram
# Layer 3 outer — KMS / KEK
box(s, 0.4, 1.35, 8.3, 5.6, BLUE,
    border_colour=TEAL, border_pt=2)
label(s, 0.55, 1.45, 7.5, 0.45,
      "LAYER 3 — Master Key (KEK)  ·  Lives entirely inside AWS KMS — never in our servers",
      font_size=12, bold=True, colour=STEEL)

# Layer 2 — DEK
box(s, 0.7, 2.05, 7.9, 4.3, PURPLE,
    border_colour=AMBER, border_pt=2)
label(s, 0.85, 2.15, 7.0, 0.45,
      "LAYER 2 — Data Key (DEK)  ·  A unique padlock generated fresh for every card",
      font_size=12, bold=True, colour=STEEL)

# Layer 1 — Card data
box(s, 0.95, 2.8, 7.5, 2.95, NAVY,
    border_colour=WHITE, border_pt=1)
label(s, 1.1, 2.9, 7.0, 0.45,
      "LAYER 1 — Encrypted Card Number (PAN)  ·  The actual card data, scrambled",
      font_size=12, bold=True, colour=WHITE)
label(s, 1.1, 3.45, 7.0, 0.4,
      "Original:    5412 7534 9823 1049",
      font_size=13, colour=LGRAY)
label(s, 1.1, 3.85, 7.0, 0.4,
      "Stored as:  ▓▒░▓▒▒░▓▒░▓▒░▓░▓▒░▓▒▓░▒░▓░▒▓▒",
      font_size=13, colour=TEAL)
label(s, 1.1, 4.25, 7.0, 0.6,
      "Meaningless without the DEK. Even if someone steals the database, they see only scrambled bytes.",
      font_size=11, colour=STEEL)

# HMAC column — right side
box(s, 9.0, 1.35, 4.0, 2.5, GREEN)
label(s, 9.15, 1.45, 3.7, 0.45,
      "FINGERPRINT (HMAC)", font_size=13, bold=True, colour=WHITE)
mlabel(s, 9.15, 2.0, 3.7, 1.75,
       ["A one-way fingerprint of",
        "the card number.",
        "",
        "Used to answer:",
        "\"Have we seen this card",
        "before?\"",
        "",
        "Cannot be reversed back",
        "to the card number."],
       font_size=12, colour=WHITE)

# Arrow from HMAC to inner
arrow_h(s, 8.35, 3.05, 0.6, TEAL, 2)

# Right summary labels
box(s, 9.0, 4.1, 4.0, 0.65, TEAL,
    "Why three layers?", font_size=13, bold=True, align=PP_ALIGN.CENTER)
mlabel(s, 9.05, 4.85, 3.9, 2.4,
       ["• Steal the database → still encrypted",
        "",
        "• Steal the DEK → still need KMS",
        "",
        "• Compromise KMS → cannot get\n  DEK without authorisation",
        "",
        "• All three together → the system\n  stays secure"],
       font_size=12, colour=STEEL)


# ════════════════════════════════════════════════════════════════════════════
# Slide 4 — KEK & DEK Analogy (Safe Deposit Box)
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, LIGHT)
header(s, "The Envelope — How the Master Key & Data Key Work Together",
       "Think of it like a bank's safe deposit box system", dark=False)

# ── Left: Analogy diagram ────────────────────────────────────────────────────
# Bank vault (outer)
box(s, 0.4, 1.35, 5.5, 5.75, NAVY)
label(s, 0.55, 1.45, 5.0, 0.4,
      "🏦  THE BANK  (AWS KMS)",
      font_size=13, bold=True, colour=TEAL)
label(s, 0.55, 1.9, 5.0, 0.55,
      "The master key (KEK) lives here.\nIt never leaves the bank.",
      font_size=12, colour=STEEL)

# Padlock inside bank
box(s, 0.8, 2.6, 4.7, 0.75, TEAL,
    "🔑  Master Key (KEK)  —  managed by AWS, never handed over",
    font_size=12, bold=True, align=PP_ALIGN.CENTER)

arrow_v(s, 3.15, 3.4, 0.5, TEAL, 2.5)
label(s, 3.25, 3.5, 1.5, 0.35,
      "unlocks", font_size=11, colour=TEAL)

# Safe deposit box
box(s, 0.8, 4.0, 4.7, 0.7, PURPLE,
    "🔐  Your padlock key (DEK) — unique per card, locked by the master key",
    font_size=12, bold=True, align=PP_ALIGN.CENTER)

arrow_v(s, 3.15, 4.75, 0.45, PURPLE, 2.5)
label(s, 3.25, 4.85, 1.5, 0.35,
      "unlocks", font_size=11, colour=PURPLE)

# Envelope inside
box(s, 0.8, 5.3, 4.7, 0.7, RED,
    "✉  The sealed envelope (encrypted PAN) — your card number inside",
    font_size=12, bold=True, align=PP_ALIGN.CENTER)

label(s, 0.55, 6.1, 5.0, 0.6,
      "Each card gets its own padlock. All padlock keys are locked by the one master key at the bank.",
      font_size=11, colour=GRAY)

# ── Right: How it works in practice ─────────────────────────────────────────
label(s, 6.2, 1.35, 6.7, 0.45,
      "What this means in practice:", font_size=15, bold=True, colour=NAVY)

steps = [
    (TEAL,   "Storing a card",
     "We generate a fresh padlock (DEK) for each card, seal\nthe card number inside, then ask the bank to lock the\npadlock. Only the locked padlock is stored — never the key."),
    (PURPLE, "Retrieving a card",
     "We take the locked padlock to the bank. The bank\nunlocks it with the master key, hands us the key\nbriefly, we open the envelope, read the card, hand\nthe key back immediately."),
    (GREEN,  "If our database is stolen",
     "The attacker gets sealed envelopes and locked\npadlocks — useless without the master key,\nwhich only the bank (AWS KMS) holds."),
    (BLUE,   "Changing the master key",
     "We collect all padlocks, ask the bank to re-lock\nthem with a new master key. The envelopes are\nnever opened — cards never exposed during rotation."),
]
for i, (colour, heading, body) in enumerate(steps):
    y = 1.9 + i * 1.35
    box(s, 6.2, y, 2.4, 1.1, colour, heading, font_size=13, bold=True,
        align=PP_ALIGN.CENTER)
    label(s, 8.75, y, 4.3, 1.1, body, font_size=12, colour=GRAY)


# ════════════════════════════════════════════════════════════════════════════
# Slide 5 — HMAC Analogy (Fingerprint)
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, NAVY)
header(s, "The Fingerprint — How We Recognise a Card Without Storing It",
       "HMAC: a one-way, deterministic fingerprint of the card number")

# Left: fingerprint diagram
# Same card → same fingerprint
box(s, 0.4, 1.35, 3.6, 0.65, RED,
    "5412 7534 9823 1049  (First visit)", font_size=13, bold=True,
    align=PP_ALIGN.CENTER)
arrow_h(s, 4.05, 1.68, 1.0, TEAL, 2.5)
box(s, 5.15, 1.35, 3.6, 0.65, GREEN,
    "Fingerprint: a7f3c8d2…", font_size=13, bold=True, align=PP_ALIGN.CENTER)

box(s, 0.4, 2.3, 3.6, 0.65, RED,
    "5412 7534 9823 1049  (Second visit)", font_size=13, bold=True,
    align=PP_ALIGN.CENTER)
arrow_h(s, 4.05, 2.63, 1.0, TEAL, 2.5)
box(s, 5.15, 2.3, 3.6, 0.65, GREEN,
    "Fingerprint: a7f3c8d2…", font_size=13, bold=True, align=PP_ALIGN.CENTER)

label(s, 5.15, 3.05, 3.6, 0.4,
      "✓  Same fingerprint — same card — return the existing token",
      font_size=12, colour=GREEN)

# Divider
box(s, 0.4, 3.6, 8.4, 0.04, GRAY)

# Different card → different fingerprint
box(s, 0.4, 3.75, 3.6, 0.65, PURPLE,
    "4111 1111 1111 1111  (Different card)", font_size=13, bold=True,
    align=PP_ALIGN.CENTER)
arrow_h(s, 4.05, 4.08, 1.0, TEAL, 2.5)
box(s, 5.15, 3.75, 3.6, 0.65, PURPLE,
    "Fingerprint: 2b9e1f4a…", font_size=13, bold=True, align=PP_ALIGN.CENTER)

label(s, 5.15, 4.5, 3.6, 0.4,
      "✓  Different fingerprint — new card — create a new token",
      font_size=12, colour=STEEL)

# Cannot reverse
box(s, 0.4, 5.15, 8.4, 0.6, AMBER,
    "a7f3c8d2…  →  ❌  Cannot reverse back to  →  ??? ??? ????",
    font_size=14, bold=True, font_colour=NAVY, align=PP_ALIGN.CENTER)
label(s, 0.4, 5.85, 8.4, 0.5,
      "A fingerprint is one-way. Knowing the fingerprint tells you nothing about the card number itself.",
      font_size=12, colour=STEEL)

# Right: why it matters
box(s, 9.0, 1.35, 4.0, 0.6, TEAL,
    "Why does this matter?", font_size=14, bold=True, align=PP_ALIGN.CENTER)

mlabel(s, 9.05, 2.05, 3.9, 5.5,
       ["Same card, different time:",
        "Returns the exact same token",
        "(deduplication — no duplicates",
        "in the vault).",
        "",
        "Recurring payments work:",
        "A subscription uses the same",
        "token each month because the",
        "card fingerprint matches.",
        "",
        "No card stored:",
        "We never store or compare",
        "the real card number —",
        "only its fingerprint.",
        "",
        "HMAC needs a secret key:",
        "Without our secret, an attacker",
        "cannot compute fingerprints and",
        "probe whether a card is in the vault."],
       font_size=12, colour=STEEL,
       line_bold=[True, False, False, False, False,
                  True, False, False, False, False,
                  True, False, False, False, False,
                  True, False, False, False])


# ════════════════════════════════════════════════════════════════════════════
# Slide 6 — Tokenisation Flow (annotated with layers)
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, LIGHT)
header(s, "Storing a Card — What Happens Step by Step", dark=False)

steps = [
    ("①", "Card arrives",
     "Customer enters card at\ncheckout. Sent over TLS.",
     NAVY, ""),
    ("②", "Fingerprint check\n(HMAC)",
     "Is this card already in\nthe vault?",
     GREEN, "If yes → return existing\ntoken immediately"),
    ("③", "Generate DEK\n& encrypt",
     "Fresh padlock (DEK) created.\nCard sealed with AES-256.",
     PURPLE, "DEK is unique per card.\nCard never touches disk\nunencrypted."),
    ("④", "Lock the DEK\nvia KMS",
     "DEK sent to AWS KMS.\nKMS locks it with the\nmaster key (KEK).",
     BLUE, "Master key stays in KMS.\nWe receive only the\nlocked DEK back."),
    ("⑤", "Store & return\ntoken",
     "Token + fingerprint +\nencrypted card + locked DEK\nstored in vault.",
     TEAL, "Token returned to merchant.\nAll key material zeroed\nfrom memory."),
]

bw = 2.3
gap = 0.1
sx = 0.3
for i, (num, title, body, colour, note) in enumerate(steps):
    x = sx + i * (bw + gap)
    box(s, x, 1.35, bw, 0.5, colour,
        f"{num}  {title}", font_size=13, bold=True, align=PP_ALIGN.CENTER)
    label(s, x + 0.1, 1.9, bw - 0.2, 1.0, body, font_size=12, colour=GRAY)
    if note:
        box(s, x, 3.05, bw, 0.85, RGBColor(0xE8, 0xF4, 0xE8),
            note, font_size=11, font_colour=RGBColor(0x1A, 0x5C, 0x1A),
            align=PP_ALIGN.CENTER)
    if i < len(steps) - 1:
        label(s, x + bw + 0.01, 1.5, 0.12, 0.35, "▶",
              font_size=14, colour=TEAL, align=PP_ALIGN.CENTER)

# What is stored diagram
label(s, 0.3, 4.1, 12.7, 0.4,
      "What ends up in the vault database for each card:", font_size=14, bold=True, colour=NAVY)

stored = [
    (TEAL,   "Token",          "3a4f9d2e-…",      "Shared with\nmerchants"),
    (GREEN,  "Fingerprint",    "a7f3c8d2-…",      "Dedup check\nonly"),
    (PURPLE, "Encrypted PAN",  "▓▒░▓▒▒░▓▒░…",     "Useless without\nthe DEK"),
    (BLUE,   "Locked DEK",     "KMS-wrapped key",  "Useless without\nthe master key"),
    (NAVY,   "Last 4 digits",  "1049",             "Safe to store;\nnot a PAN"),
]
for i, (colour, name, value, note) in enumerate(stored):
    x = 0.3 + i * 2.6
    box(s, x, 4.6, 2.45, 0.5, colour, name, font_size=13, bold=True, align=PP_ALIGN.CENTER)
    label(s, x + 0.1, 5.15, 2.3, 0.4, value, font_size=11, colour=GRAY)
    label(s, x + 0.1, 5.55, 2.3, 0.55, note, font_size=11, colour=GRAY)

box(s, 0.3, 6.3, 12.7, 0.65, NAVY,
    "The real card number (PAN) is never written to the database — only its encrypted form and a one-way fingerprint.",
    font_size=14, bold=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# Slide 7 — Detokenisation Flow (annotated with layers)
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, LIGHT)
header(s, "Retrieving a Card — What Happens Step by Step", dark=False)

steps2 = [
    ("①", "Token arrives",
     "Payment processor sends\ntoken. Rate-limited:\n10,000 / minute / caller.",
     NAVY, "Every request is\nlogged with who,\nwhen, and which token."),
    ("②", "Vault lookup",
     "Encrypted PAN + locked\nDEK fetched from vault\nusing the token.",
     TEAL, "Lookup is by token only.\nNo PAN in the query."),
    ("③", "Unlock DEK\nvia KMS",
     "Locked DEK sent to\nAWS KMS. KMS checks\nauthorisation, unlocks it.",
     BLUE, "KMS denies if caller\nlacks permission or\nkey is disabled."),
    ("④", "Decrypt card",
     "DEK used to decrypt\nthe encrypted PAN.\nOriginal card recovered.",
     PURPLE, "DEK lives in memory\nfor < 1 millisecond.\nZeroed immediately after."),
    ("⑤", "Return & discard",
     "Card returned to\ncaller over TLS.\nDEK erased from memory.",
     GREEN, "Nothing added to\nthe database.\nPure read operation."),
]

for i, (num, title, body, colour, note) in enumerate(steps2):
    x = sx + i * (bw + gap)
    box(s, x, 1.35, bw, 0.5, colour,
        f"{num}  {title}", font_size=13, bold=True, align=PP_ALIGN.CENTER)
    label(s, x + 0.1, 1.9, bw - 0.2, 1.05, body, font_size=12, colour=GRAY)
    if note:
        box(s, x, 3.05, bw, 0.85, RGBColor(0xE8, 0xEE, 0xF8),
            note, font_size=11, font_colour=BLUE, align=PP_ALIGN.CENTER)
    if i < len(steps2) - 1:
        label(s, x + bw + 0.01, 1.5, 0.12, 0.35, "▶",
              font_size=14, colour=TEAL, align=PP_ALIGN.CENTER)

# Security callout row
label(s, 0.3, 4.1, 12.7, 0.4,
      "What makes detokenisation secure:", font_size=14, bold=True, colour=NAVY)

security = [
    (TEAL,   "Rate Limited",
     "Max 10,000 requests\nper minute per caller.\nBulk enumeration is\nimpossible."),
    (BLUE,   "KMS Authorised",
     "AWS KMS enforces\nwho can unlock DEKs.\nUnauthorised callers\nare rejected."),
    (PURPLE, "Key Zeroed",
     "DEK exists in memory\nfor < 1 ms.\nNo key material\npersists after use."),
    (GREEN,  "Fully Audited",
     "Every access is written\nto an append-only\naudit log.\nReady for regulators."),
    (AMBER,  "Tamper Detected",
     "GCM auth tag on every\nciphertext. Any byte\nchanged in the database\nfails decryption."),
]
for i, (colour, name, body) in enumerate(security):
    x = 0.3 + i * 2.6
    box(s, x, 4.6, 2.45, 0.55, colour, name, font_size=13, bold=True,
        align=PP_ALIGN.CENTER, font_colour=NAVY if colour == AMBER else WHITE)
    label(s, x + 0.1, 5.2, 2.3, 1.1, body, font_size=11, colour=GRAY)

box(s, 0.3, 6.45, 12.7, 0.65, NAVY,
    "The card number (PAN) only exists in plain text for the fraction of a second needed to return it — never stored, never logged.",
    font_size=14, bold=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# Slide 8 — Key Rotation
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, NAVY)
header(s, "Keeping Keys Fresh — Automatic Key Rotation",
       "Cryptographic keys are like passwords: they should be changed regularly, even if not compromised.")

# Timeline
label(s, 0.4, 1.0, 12.5, 0.4,
      "What happens when we rotate:", font_size=14, bold=True, colour=WHITE)

timeline = [
    (TEAL,  "①  New KEK\ncreated in KMS", "AWS KMS generates\na new master key"),
    (PURPLE,"②  DEKs re-locked",           "Every card's padlock\nkey re-locked under\nthe new master key"),
    (GREEN, "③  Old KEK\nretired",          "Old master key\nmarked retired.\nNo new DEKs use it."),
    (BLUE,  "④  Cards unchanged",           "Encrypted card data\nunchanged.\nNo decryption needed."),
]
for i, (colour, title, body) in enumerate(timeline):
    x = 0.5 + i * 3.1
    box(s, x, 1.5, 2.8, 0.9, colour, title, font_size=13, bold=True, align=PP_ALIGN.CENTER)
    label(s, x + 0.1, 2.5, 2.6, 0.75, body, font_size=12, colour=STEEL)
    if i < len(timeline) - 1:
        label(s, x + 2.82, 1.85, 0.3, 0.4, "▶", font_size=16, colour=TEAL, align=PP_ALIGN.CENTER)

box(s, 0.4, 3.4, 12.5, 0.55, TEAL,
    "Zero downtime. Merchants keep using the same tokens. Nothing visible changes — only the locks behind the scenes.",
    font_size=14, bold=True, align=PP_ALIGN.CENTER)

# Two columns: scheduled vs emergency
for i, (colour, title, items) in enumerate([
    (BLUE, "Scheduled Rotation  (every 12 months)",
     ["Triggered automatically when a key\napproaches its compliance age limit",
      "Runs overnight — no user impact",
      "Required by PCI-DSS"]),
    (RED, "Emergency Rotation  (within minutes)",
     ["Triggered immediately if a key is\nsuspected compromised",
      "Old key blocked — all old tokens\nstill detokenisable under the new key",
      "Full audit trail created automatically"]),
]):
    x = 0.4 + i * 6.5
    box(s, x, 4.15, 6.1, 0.6, colour, title, font_size=14, bold=True, align=PP_ALIGN.CENTER)
    for j, item in enumerate(items):
        label(s, x + 0.2, 4.9 + j * 0.55, 5.8, 0.5,
              f"• {item}", font_size=13, colour=STEEL)


# ════════════════════════════════════════════════════════════════════════════
# Slide 9 — Business Summary
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank)
bg(s, TEAL)
box(s, 0, 0, 13.33, 0.18, NAVY)
box(s, 0, 7.32, 13.33, 0.18, NAVY)

label(s, 0.5, 0.3, 12.3, 0.65,
      "What This Means for the Business",
      font_size=32, bold=True, colour=WHITE, align=PP_ALIGN.CENTER)

benefits = [
    (NAVY,   "🛡  Reduced Risk",
     "Card numbers never leave the vault.\nA breach of any merchant or payment\nsystem exposes only tokens —\nuseless to a fraudster."),
    (BLUE,   "📉  Smaller Compliance Scope",
     "Systems that handle only tokens are\nlargely out of PCI-DSS card-data scope.\nFewer systems to audit means\nlower compliance cost."),
    (PURPLE, "🔁  No Disruption",
     "Tokens survive key rotations and\ncard renewals. Merchants update\none record; downstream systems\nsee no change."),
    (GREEN,  "📋  Full Audit Trail",
     "Every tokenisation and detokenisation\nis logged with who, when, and what.\nReady for a regulatory inspection\nat any time."),
    (AMBER,  "⚡  Zero Downtime Operations",
     "Key rotation and emergency\nre-encryption run automatically\nin the background while the payment\nsystem remains fully live."),
]
positions = [
    (0.4, 1.15), (4.65, 1.15), (8.9, 1.15),
    (2.5, 4.1),  (6.75, 4.1),
]
for (x, y), (colour, title, body) in zip(positions, benefits):
    box(s, x, y, 3.9, 0.6, colour, title, font_size=13, bold=True,
        align=PP_ALIGN.CENTER,
        font_colour=NAVY if colour == AMBER else WHITE)
    label(s, x + 0.15, y + 0.65, 3.6, 1.65, body, font_size=12, colour=WHITE)


import os
out = os.path.join(os.path.dirname(__file__), "card-tokenisation-overview.pptx")
prs.save(out)
print(f"Saved: {out}  ({len(prs.slides)} slides)")
