# Zashi — Character Brand & Variation Generation Guide

**Zashi** is the official mascot of **Zashu** (Zero-Knowledge Solvency & Shielded Ecash for Cashu). This guide defines the strict visual invariants, color palette, trait matrix, and prompt template for generating new, consistent Zashi variations.

---

## 1. Non-Negotiable Base Invariants

Every Zashi variation **must** preserve these core traits so the character stays instantly recognizable across the landing page, playground, docs, and video:

| Rule | Specification |
| :--- | :--- |
| **Silhouette** | Chubby, cute golden-tan **cashew nut** body (soft curved bean/crescent silhouette). |
| **Pose & Direction** | 3/4 view **facing and looking to the RIGHT**, floating slightly above a small dark oval drop-shadow. |
| **Limbs (NO SHOES)** | Stubby rounded nub arms and stubby rounded nub feet—**never** draw shoes, boots, sneakers, or detailed human fingers. |
| **Privacy Motif** | Always wears a **dark-violet ZK visor / domino mask** or **lower ninja cloth mask** (eyes either glowing subtly through the visor or peeking cleanly above the cloth mask). |
| **Art Style** | Crisp **2D flat-vector / cel-shaded** illustration with thick, clean dark outlines. No photorealism, no 3D clay renders, no blurry gradients. |
| **Background & Text** | Solid **Deep Obsidian (`#0A0D14`)** background, centered composition, **zero text or watermarks**. |

---

## 2. Official Color Palette

| Role | Hex | Usage |
| :--- | :--- | :--- |
| **Background** | `#0A0D14` | Deep Obsidian canvas (matches `landing.html` & `playground.html`) |
| **Body Fill** | `#E6B86A` | Warm golden-tan cashew body |
| **Primary Brand Accent** | `#8B5CF6` / `#4C1D95` | ZK Violet — masks, visors, headbands, glowing ZK effects |
| **Bitcoin Accent** | `#F7931A` | Bitcoin Amber — trim, scrolls, padlock pins, knots, glowing bowls |
| **Verification Accent** | `#2EA043` / `#3FB950` | Emerald — solvency seals, verified shields |
| **Sakura Accent** | `#F5A9CB` | Soft pink — Zakura petals & blossoms |

---

## 3. Canonical Prompt Template

Always anchor new generations to the canonical base reference image (`assets/zashi-mascot.jpg`):

```text
Using assets/zashi-mascot.jpg as the exact base character (same right-facing chubby
golden-tan cashew nut with stubby rounded nub arms and stubby rounded nub feet, NO shoes,
floating slightly above a small dark oval shadow on solid #0A0D14 deep obsidian background,
thick clean dark outlines, no text), create the "<VARIATION_NAME>" variation:
dress Zashi in <OUTFIT_DESCRIPTION>, wearing <HEADGEAR_OR_MASK_TWIST>, holding
<PROP_OR_ACCESSORY>. Centered composition, crisp 2D flat-vector art, no text.
```

### Quality Checklist Before Accepting a Variation
1. Is Zashi **facing right**?
2. Are the feet **bare stubby rounded nubs** (zero shoes/boots)?
3. Is there a **floating oval drop-shadow** underneath on `#0A0D14`?
4. Are there **zero letters, logos, or garbled text** anywhere in the image?
5. Do the colors harmonize with **ZK Violet (`#8B5CF6`)** and **Bitcoin Amber (`#F7931A`)**?

---

## 4. Official Variation Roster

| File | Name | Theme / Tribute | Key Accessories |
| :--- | :--- | :--- | :--- |
| `assets/zashi-mascot.jpg` *(copy of streetwear)* | **Streetwear Ninja** *(Main)* | Default Zashu brand | Oversized dark-violet hoodie, ZK visor, Bitcoin-amber scroll |
| `assets/zashi-var-zakura.jpg` | **Zakura** | Sakura / Zcash-Japan tribute | Sakura-pink & violet haori, folding *sensu* fan, drifting petals |
| `assets/zashi-var-satoshi.jpg` | **Satoshi Ronin** | Satoshi Nakamoto tribute | Obsidian & amber ronin cloak, lacquered *kasa* hat, glowing whitepaper scroll |
| `assets/zashi-var-cyber.jpg` | **Cyber Shinobi** | Cryptographic security | Flowing violet scarf, charcoal tactical vest, amber padlock pin |
| `assets/zashi-var-monk.jpg` | **Shadow Monk** | Stealth & calm | Indigo *haori* jacket, tilted *kasa* hat, glowing violet privacy lantern |
| `assets/zashi-var-kitsune.jpg` | **Kitsune** | Japanese folklore / ZK illusion | Shrine *haori*, white-and-violet fox mask worn over face, glowing *kitsunebi* orb |
| `assets/zashi-var-tachyon.jpg` | **Tachyon** | Swiftness & pruning | Aerodynamic shinobi suit, electric speed-line scarf, accumulator prism |
| `assets/zashi-var-ragu.jpg` | **Ragu Chef** | Ragu folding & Japanese craft | Indigo *happi* coat, *hachimaki* headband, steaming bowl of golden ragu/ramen |

---

## 5. Adding a New Variation to the Repo

1. Save the image to `assets/zashi-var-<slug>.jpg` and copy to `video/public/assets/zashi-var-<slug>.jpg`.
2. Add a route `/assets/zashi-var-<slug>.jpg` in `crates/zashu-mint/src/playground.rs` via `include_bytes!`.
3. Add a `.skin-card` entry to the `#zashi` gallery in `crates/zashu-mint/src/landing.html`.
4. Run `cargo test --release -p zashu-mint --test playground_e2e --offline` to verify compilation and asset serving.
