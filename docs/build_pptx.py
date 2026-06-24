"""
Rebuild card-tokenisation-overview.pptx with 5 slides for a non-technical audience.
Run: python3 docs/build_pptx.py
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
import copy

# ── Palette ──────────────────────────────────────────────────────────────────
NAVY   = RGBColor(0x0D, 0x1B, 0x3E)   # slide background / headings
TEAL   = RGBColor(0x00, 0x87, 0x8A)   # accent / rule
WHITE  = RGBColor(0xFF, 0xFF, 0xFF)
LGRAY  = RGBColor(0xF2, 0xF4, 0xF7)   # content box background
DGRAY  = RGBColor(0x44, 0x44, 0x55)   # body text
GREEN  = RGBColor(0x1A, 0x9E, 0x5C)   # benefit bullets
AMBER  = RGBColor(0xE6, 0x8A, 0x00)   # warning / cost callout
RED    = RGBColor(0xC0, 0x39, 0x2B)   # problem

W = Inches(13.33)   # 16:9 widescreen width
H = Inches(7.5)

prs = Presentation()
prs.slide_width  = W
prs.slide_height = H

blank_layout = prs.slide_layouts[6]   # completely blank

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def add_slide():
    return prs.slides.add_slide(blank_layout)

def fill_slide(slide, color):
    from pptx.util import Pt
    from pptx.dml.color import RGBColor
    from pptx.oxml.ns import qn
    import lxml.etree as etree
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color

def add_rect(slide, left, top, width, height, fill_color=None, line_color=None, line_width=Pt(0)):
    shape = slide.shapes.add_shape(
        1,  # MSO_SHAPE_TYPE.RECTANGLE
        left, top, width, height
    )
    shape.line.width = line_width
    if fill_color:
        shape.fill.solid()
        shape.fill.fore_color.rgb = fill_color
    else:
        shape.fill.background()
    if line_color:
        shape.line.color.rgb = line_color
    else:
        shape.line.fill.background()
    return shape

def add_textbox(slide, text, left, top, width, height,
                font_size=Pt(14), bold=False, color=WHITE,
                align=PP_ALIGN.LEFT, wrap=True, italic=False):
    txb = slide.shapes.add_textbox(left, top, width, height)
    tf  = txb.text_frame
    tf.word_wrap = wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size  = font_size
    run.font.bold  = bold
    run.font.color.rgb = color
    run.font.italic = italic
    return txb

def add_para(tf, text, font_size=Pt(13), bold=False, color=DGRAY,
             align=PP_ALIGN.LEFT, space_before=Pt(4), italic=False):
    p = tf.add_paragraph()
    p.alignment = align
    p.space_before = space_before
    run = p.add_run()
    run.text = text
    run.font.size  = font_size
    run.font.bold  = bold
    run.font.color.rgb = color
    run.font.italic = italic
    return p

def add_bullet_box(slide, bullets, left, top, width, height,
                   bg=LGRAY, bullet_color=TEAL, text_color=DGRAY,
                   font_size=Pt(13), title=None, title_color=NAVY):
    rect = add_rect(slide, left, top, width, height, fill_color=bg)
    txb  = slide.shapes.add_textbox(left + Inches(0.18), top + Inches(0.15),
                                     width - Inches(0.36), height - Inches(0.3))
    tf = txb.text_frame
    tf.word_wrap = True
    first = True
    if title:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.space_before = Pt(0)
        run = p.add_run()
        run.text = title
        run.font.size  = Pt(14)
        run.font.bold  = True
        run.font.color.rgb = title_color
    for b in bullets:
        p = tf.paragraphs[0] if (first and not title) else tf.add_paragraph()
        first = False
        p.space_before = Pt(5)
        run = p.add_run()
        run.text = b
        run.font.size  = font_size
        run.font.color.rgb = text_color
    return rect

def accent_bar(slide, y=Inches(0.58)):
    add_rect(slide, Inches(0.5), y, Inches(12.33), Pt(3), fill_color=TEAL)

def slide_title(slide, text, y=Inches(0.15), font_size=Pt(32)):
    add_textbox(slide, text, Inches(0.5), y, Inches(12.5), Inches(0.55),
                font_size=font_size, bold=True, color=WHITE, align=PP_ALIGN.LEFT)

def footer(slide, text="Card Tokenisation System  |  Confidential"):
    add_textbox(slide, text,
                Inches(0.5), H - Inches(0.35), Inches(12), Inches(0.3),
                font_size=Pt(9), color=RGBColor(0xAA, 0xAA, 0xBB),
                align=PP_ALIGN.LEFT)

# ─────────────────────────────────────────────────────────────────────────────
# SLIDE 1 — Problem & Benefits (with KMS cost callout)
# ─────────────────────────────────────────────────────────────────────────────
s1 = add_slide()
fill_slide(s1, NAVY)

slide_title(s1, "Protecting Card Numbers Without the Risk", y=Inches(0.12))
accent_bar(s1)

# Problem column
add_rect(s1, Inches(0.5), Inches(0.75), Inches(5.9), Inches(0.38), fill_color=RED)
add_textbox(s1, "The Problem", Inches(0.6), Inches(0.77), Inches(5.7), Inches(0.34),
            font_size=Pt(15), bold=True, color=WHITE)

add_bullet_box(s1,
    [
        "  Card numbers (PANs) are sensitive — a breach exposes real cardholder data.",
        "  Merchants need to reference a payment card repeatedly (subscriptions, refunds).",
        "  Storing the raw card number anywhere creates liability under PCI-DSS.",
        "  Encryption alone is not enough if all records share the same key.",
    ],
    Inches(0.5), Inches(1.18), Inches(5.9), Inches(2.4),
    bg=RGBColor(0xF9, 0xEB, 0xE9), text_color=RGBColor(0x55, 0x22, 0x22),
    font_size=Pt(12.5),
)

# Benefits column
add_rect(s1, Inches(6.83), Inches(0.75), Inches(6.0), Inches(0.38), fill_color=GREEN)
add_textbox(s1, "What Tokenisation Gives You", Inches(6.93), Inches(0.77), Inches(5.8), Inches(0.34),
            font_size=Pt(15), bold=True, color=WHITE)

add_bullet_box(s1,
    [
        "  A safe, meaningless token replaces the card number everywhere outside the vault.",
        "  The vault is the only place PANs exist — encrypted at every layer.",
        "  A breach of merchant systems exposes nothing useful without vault access.",
        "  Supports refunds, subscriptions, and disputes without re-collecting card data.",
        "  Meets PCI-DSS scope reduction requirements.",
    ],
    Inches(6.83), Inches(1.18), Inches(6.0), Inches(2.4),
    bg=RGBColor(0xE8, 0xF7, 0xEE), text_color=RGBColor(0x11, 0x44, 0x22),
    font_size=Pt(12.5),
)

# KMS cost callout — wide box at bottom
add_rect(s1, Inches(0.5), Inches(3.75), Inches(12.33), Inches(0.38), fill_color=TEAL)
add_textbox(s1, "Cost of Security — Designed to be Near-Zero at Scale",
            Inches(0.6), Inches(3.77), Inches(12.0), Inches(0.34),
            font_size=Pt(15), bold=True, color=WHITE)

add_bullet_box(s1,
    [
        "  AWS KMS is called exactly 2 times at application startup — to load the master keys into secure memory.",
        "  Every tokenisation and detokenisation after that uses only in-memory cryptography — 0 KMS calls.",
        "  A key rotation (scheduled or emergency) costs exactly 1 KMS call, regardless of vault size.",
        "  Scaling from 1,000 to 10,000,000 tokens does not increase KMS costs. "
        "KMS costs scale with key events, not token volume.",
    ],
    Inches(0.5), Inches(4.18), Inches(12.33), Inches(2.6),
    bg=RGBColor(0xE6, 0xF4, 0xF5), text_color=DGRAY,
    font_size=Pt(12.5),
    title=None,
)

footer(s1)

# ─────────────────────────────────────────────────────────────────────────────
# SLIDE 2 — Layers of Protection (Analogy)
# ─────────────────────────────────────────────────────────────────────────────
s2 = add_slide()
fill_slide(s2, NAVY)

slide_title(s2, "Three Layers of Protection — Like a Bank Safe")
accent_bar(s2)

# Analogy intro
add_textbox(s2,
    "Think of it as a bank vault with a layered key system:",
    Inches(0.5), Inches(0.72), Inches(12.0), Inches(0.35),
    font_size=Pt(14), color=RGBColor(0xCC, 0xDD, 0xFF), italic=True)

layers = [
    (TEAL,  "Layer 1 — AWS KMS Master Key (CMK)",
     "Lives inside AWS's hardware security module (HSM). Never leaves AWS. "
     "Think of this as the bank's central vault that even we cannot open directly — "
     "we can only ask AWS to use it on our behalf."),
    (RGBColor(0x5B, 0x6A, 0xBE), "Layer 2 — Key Encryption Key (KEK)",
     "A 32-byte key that the application holds in RAM (never on disk). "
     "It is unlocked from AWS KMS at startup and used to lock/unlock individual card keys. "
     "Analogy: the combination to the safe that holds the house keys. "
     "Rotating the KEK re-locks every house key under a new combination — 0 extra KMS calls."),
    (RGBColor(0x8E, 0x44, 0xAD), "Layer 3 — Data Encryption Key (DEK)",
     "A unique 32-byte key generated fresh for every card number. "
     "Each DEK exists in RAM for milliseconds — zeroed after use. "
     "Analogy: a house key. One per card. Locked in the safe (encrypted by KEK). "
     "If one house key is somehow stolen, only one card is at risk — nothing else."),
]

for i, (color, title, body) in enumerate(layers):
    top = Inches(1.12) + i * Inches(1.88)
    add_rect(s2, Inches(0.5), top, Inches(0.28), Inches(1.72), fill_color=color)
    add_rect(s2, Inches(0.82), top, Inches(11.9), Inches(1.72), fill_color=LGRAY)
    add_textbox(s2, title,
                Inches(1.0), top + Inches(0.1), Inches(11.5), Inches(0.38),
                font_size=Pt(15), bold=True, color=NAVY)
    add_textbox(s2, body,
                Inches(1.0), top + Inches(0.5), Inches(11.5), Inches(1.1),
                font_size=Pt(13), color=DGRAY, wrap=True)

# HMAC callout
add_rect(s2, Inches(0.5), Inches(6.75), Inches(12.33), Inches(0.38), fill_color=AMBER)
add_textbox(s2,
    "Also: HMAC fingerprint — a one-way hash of the card number used only to detect duplicates. "
    "Cannot be reversed to recover the card. Protected directly by AWS KMS.",
    Inches(0.6), Inches(6.77), Inches(12.1), Inches(0.34),
    font_size=Pt(12), color=WHITE)

footer(s2)

# ─────────────────────────────────────────────────────────────────────────────
# SLIDE 3 — Tokenisation Flow
# ─────────────────────────────────────────────────────────────────────────────
s3 = add_slide()
fill_slide(s3, NAVY)

slide_title(s3, "Tokenisation — Turning a Card Number Into a Safe Token")
accent_bar(s3)

add_textbox(s3,
    "Trigger: merchant sends  POST /api/v1/tokens  with the card number.   0 KMS calls.",
    Inches(0.5), Inches(0.72), Inches(12.5), Inches(0.32),
    font_size=Pt(13), color=RGBColor(0xCC, 0xDD, 0xFF), italic=True)

steps = [
    (GREEN,  "1  Generate a unique key (DEK)",
     "A fresh 32-byte random key is created just for this card — lives in memory only."),
    (GREEN,  "2  Encrypt the card number",
     "AES-256-GCM encrypts the PAN using the DEK. The DEK is zeroed from memory immediately after."),
    (GREEN,  "3  Lock the DEK away",
     "The DEK is itself encrypted (wrapped) using the in-memory KEK. The locked DEK is stored, not the original."),
    (TEAL,   "4  Fingerprint for duplicate detection",
     "HMAC-SHA256 creates a one-way hash of the card number. Used to return the same token if this card arrives again."),
    (TEAL,   "5  Duplicate check",
     "Database lookup: does this fingerprint already exist? If yes — return the existing token immediately (no new row)."),
    (AMBER,  "6  Store in the vault",
     "A new vault row is created: token UUID, encrypted card, locked DEK, fingerprint. The raw card number never touches the database."),
    (RGBColor(0x44,0x88,0xCC), "7  Return the token",
     "The caller receives only the token UUID and last-four digits. The card number leaves the application immediately."),
]

box_h = Inches(0.72)
for i, (color, title, body) in enumerate(steps):
    top = Inches(1.08) + i * (box_h + Inches(0.04))
    add_rect(s3, Inches(0.5), top, Inches(0.25), box_h, fill_color=color)
    add_rect(s3, Inches(0.79), top, Inches(12.0), box_h, fill_color=LGRAY)
    add_textbox(s3, title,
                Inches(0.95), top + Inches(0.04), Inches(3.8), Inches(0.35),
                font_size=Pt(13), bold=True, color=NAVY)
    add_textbox(s3, body,
                Inches(4.9), top + Inches(0.04), Inches(7.7), Inches(0.6),
                font_size=Pt(12.5), color=DGRAY, wrap=True)

footer(s3)

# ─────────────────────────────────────────────────────────────────────────────
# SLIDE 4 — Detokenisation Flow
# ─────────────────────────────────────────────────────────────────────────────
s4 = add_slide()
fill_slide(s4, NAVY)

slide_title(s4, "Detokenisation — Recovering the Card Number From a Token")
accent_bar(s4)

add_textbox(s4,
    "Trigger: authorised system sends  GET /api/v1/tokens/{token}.   0 KMS calls.",
    Inches(0.5), Inches(0.72), Inches(12.5), Inches(0.32),
    font_size=Pt(13), color=RGBColor(0xCC, 0xDD, 0xFF), italic=True)

det_steps = [
    (TEAL,   "1  Look up the vault",
     "Database query: find the vault row matching this token UUID. Retrieve encrypted card, locked DEK, and which key version encrypted it."),
    (TEAL,   "2  Find the right key (in memory)",
     "The Key Ring holds all active and rotating KEK versions in RAM. No KMS call needed — the KEK is already there from startup."),
    (RED,    "3  Safety check",
     "If the key was marked COMPROMISED (emergency rotation), access is blocked immediately and an alert is written. No card is returned."),
    (GREEN,  "4  Unlock the DEK",
     "AES-256-GCM decrypts the locked DEK using the in-memory KEK. The unlocked DEK exists in RAM for milliseconds."),
    (GREEN,  "5  Recover the card number",
     "AES-256-GCM decrypts the encrypted card using the DEK. The authentication tag is verified — any tampering is detected here."),
    (GREEN,  "6  Zero the DEK",
     "The unlocked DEK bytes are immediately overwritten with zeros and discarded. No sensitive key material lingers."),
    (RGBColor(0x44,0x88,0xCC), "7  Return the card number",
     "The caller receives the PAN and last-four digits. The HMAC fingerprint is never consulted — it plays no role in detokenisation."),
]

for i, (color, title, body) in enumerate(det_steps):
    top = Inches(1.08) + i * (box_h + Inches(0.04))
    add_rect(s4, Inches(0.5), top, Inches(0.25), box_h, fill_color=color)
    add_rect(s4, Inches(0.79), top, Inches(12.0), box_h, fill_color=LGRAY)
    add_textbox(s4, title,
                Inches(0.95), top + Inches(0.04), Inches(3.8), Inches(0.35),
                font_size=Pt(13), bold=True, color=NAVY)
    add_textbox(s4, body,
                Inches(4.9), top + Inches(0.04), Inches(7.7), Inches(0.6),
                font_size=Pt(12.5), color=DGRAY, wrap=True)

footer(s4)

# ─────────────────────────────────────────────────────────────────────────────
# SLIDE 5 — Key Rotation
# ─────────────────────────────────────────────────────────────────────────────
s5 = add_slide()
fill_slide(s5, NAVY)

slide_title(s5, "Key Rotation — Changing the Locks Without Closing the Vault")
accent_bar(s5)

add_textbox(s5,
    "Keys are rotated on a schedule or immediately in an emergency. "
    "Every rotation costs exactly 1 KMS call. No downtime. No restarting.",
    Inches(0.5), Inches(0.72), Inches(12.5), Inches(0.42),
    font_size=Pt(13), color=RGBColor(0xCC, 0xDD, 0xFF), italic=True)

# Two columns: Scheduled KEK rotation | Emergency rotation
col_w  = Inches(5.9)
col_gap = Inches(0.53)

# ── Scheduled KEK Rotation ───────────────────────────────────────────────────
add_rect(s5, Inches(0.5), Inches(1.22), col_w, Inches(0.38), fill_color=TEAL)
add_textbox(s5, "Scheduled KEK Rotation", Inches(0.6), Inches(1.24), col_w - Inches(0.2), Inches(0.34),
            font_size=Pt(15), bold=True, color=WHITE)

kek_bullets = [
    "1  New KEK generated in memory + 1 KMS call to protect it",
    "2  New KEK goes ACTIVE; old KEK moves to ROTATING",
    "3  New tokens immediately use the new key",
    "4  Background job (every 15 min) re-wraps each token's DEK under the new KEK  — 0 KMS calls per token",
    "5  Once all tokens migrated, old KEK is retired from memory",
    "",
    "During rotation:  old tokens remain readable (old KEK still in memory)",
    "After rotation:   all tokens on new key; old key gone",
    "HMAC key:  completely unaffected",
]
add_bullet_box(s5, kek_bullets, Inches(0.5), Inches(1.65), col_w, Inches(4.0),
               font_size=Pt(12), text_color=DGRAY, bg=LGRAY)

# ── HMAC Rotation ────────────────────────────────────────────────────────────
add_rect(s5, Inches(0.5) + col_w + col_gap, Inches(1.22), col_w, Inches(0.38), fill_color=RGBColor(0x5B, 0x6A, 0xBE))
add_textbox(s5, "HMAC Key Rotation", Inches(0.6) + col_w + col_gap, Inches(1.24), col_w - Inches(0.2), Inches(0.34),
            font_size=Pt(15), bold=True, color=WHITE)

hmac_bullets = [
    "1  New HMAC secret generated in memory + 1 KMS call to protect it",
    "2  New HMAC goes ACTIVE; old HMAC moves to ROTATING",
    "3  New tokenisations immediately fingerprint with new secret",
    "4  Nightly batch re-hashes all vault fingerprints  — 0 KMS calls per token",
    "   (Each PAN briefly decrypted in memory to re-hash — most sensitive batch)",
    "5  Once all records re-hashed, old HMAC is retired",
    "",
    "Detokenisation:  completely unaffected (never reads the fingerprint)",
    "KEK:  completely unaffected",
]
add_bullet_box(s5, hmac_bullets, Inches(0.5) + col_w + col_gap, Inches(1.65), col_w, Inches(4.0),
               font_size=Pt(12), text_color=DGRAY, bg=LGRAY)

# ── Emergency Rotation ───────────────────────────────────────────────────────
add_rect(s5, Inches(0.5), Inches(5.82), Inches(12.33), Inches(0.38), fill_color=RED)
add_textbox(s5, "Emergency Rotation (KEK suspected compromised)",
            Inches(0.6), Inches(5.84), Inches(12.1), Inches(0.34),
            font_size=Pt(15), bold=True, color=WHITE)

add_bullet_box(s5,
    [
        "  Old KEK immediately marked COMPROMISED (synchronous — happens before the API returns).",
        "  Any detokenisation attempt on a COMPROMISED key is blocked and audited — no card data returned until migration completes.",
        "  Background job migrates all affected tokens to the new key at maximum speed.",
        "  Intentional brief downtime for affected tokens is the correct security response when a key may be compromised.",
    ],
    Inches(0.5), Inches(6.25), Inches(12.33), Inches(1.0),
    bg=RGBColor(0xF9, 0xEB, 0xE9), text_color=RGBColor(0x55, 0x11, 0x11),
    font_size=Pt(12),
)

footer(s5)

# ─────────────────────────────────────────────────────────────────────────────
out = "docs/card-tokenisation-overview.pptx"
prs.save(out)
print(f"Saved {out}")
