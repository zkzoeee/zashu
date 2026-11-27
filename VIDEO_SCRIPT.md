# Zashu — 61-Second Motion Demo

**Title:** *Zashu: Cashu Speed, Shinobi Privacy*
**Duration:** 61.2 s (1,836 frames @ 30 fps)
**Formats:** 16:9 (`1920x1080`) and 9:16 (`1080x1920`). Each scene has its own layout for each format; nothing is just cropped.
**Audio:** Burned-in captions (made for muted autoplay), synthesized SFX, and a calm Japanese-style ambient music bed. No voice-over.
**Type:** The **Zashu** wordmark and the hanko stamps (BLOCKED / SOLVENT) use *Reggae One*, a Japanese display face, in one color (light ZK violet `#c4b5fd`). All other text uses the system sans font.

## Story logic

1. **Respectful problem framing.** The hook says where Cashu *could go further*, not that it is broken. Every claim matches how Cashu works today:
   * The mint sees token denominations, and power-of-2 splits *can* fingerprint amounts.
   * P2PK-locked payments (NUT-11) put the receiver's key in the token, so the mint sees who gets paid.
   * Mints are custodial, and there is no standard proof that a mint is fully backed. A Proof of Liabilities proposal and community auditor tools exist, but neither proves reserves.
2. **Cashu-native before features.** Before any feature, show that Zashu lives *inside* the same Cashu mint. It shares one Lightning backend and one solvency proof, uses zero-fee shield/unshield, and existing wallets keep working.
3. **Show the reveal.** Every feature scene has one visual twist.
4. **Real numbers only.** Every figure comes from `BENCHMARKS.md` or the NUTZ specs.

## Storyboard

| Time | Scene | Visual | Caption | SFX |
| :--- | :--- | :--- | :--- | :--- |
| 0:00–0:05 | **Hook** | "Cashu is *fast.*" punches in, then shrinks. "Where it could go further:" Three amber → points: power-of-2 splits can fingerprint amounts · locked payments show the mint who gets paid · no standard proof a mint is fully backed. | *(the on-screen text is the caption)* | thump, whoosh, ticks |
| 0:05–0:08.5 | **Title** | Katana slash. Zashi drops in. **Zashu** wordmark (Reggae One, single violet). "Zero-knowledge privacy & solvency proofs for Cashu" · *Same mint · Same Lightning · Drop-in*. | — | shing, thump |
| 0:08.5–0:16.5 | **Cashu-native** | "🏯 One Cashu mint" frame with a **Cashu** lane (BDHKE: instant payments, existing wallets unchanged) and a **Zashu** lane (ZK notes: private amounts & receivers, hidden spending rules). A `137` token shields across (orange → violet) and unshields back, with a "0 sat fee" chip. Shared bars slide in: *One Lightning backend for both* · *One solvency proof covers Cashu + Zashu*. | "Zashu runs inside your existing Cashu mint." → "Shield or unshield anytime, for 0 sats. Cashu wallets keep working." → "Same mint. Same Lightning. One audit for everything." | ticks, whooshes, clinks, chime |
| 0:16.5–0:26.5 | **Shield** `NUTZ-2` | 128/8/1 coins. A red scan labels them 2⁷/2³/2⁰. A slash collapses them into one note: **You see 137 sats** / **Mint sees `cm 0x7c1b…`**. | "Cashu tokens come in powers of 2, and the split can fingerprint your amount." → "Zashu shields them into one note. Any amount. Hidden from the mint." | clinks, buzz, shing, thump |
| 0:26.5–0:36.5 | **Stealth** `NUTZ-3` | Alice (Zakura) → Mint (only hashes) → Bob (Shadow Monk, offline). The payment waits, confirmed. Bob wakes and gets **+37 sats**. | "Pay Bob's zsp1 stealth address, even while he's offline." → "The mint checks the math. It never sees who, or how much." → "Bob comes online later. The payment is already his." | whoosh, ticks, chime |
| 0:36.5–0:41 | **Safety** | A replayed note bounces off Cyber Shinobi's shield. **BLOCKED** hanko. | "Spend a note twice? Its nullifier is already on record." | thump, glitch |
| 0:41–0:51.7 | **Solvency** `NUTZ-1` | Ragu Chef plus 64 proof tiles fold into one **16 KB** block, which holds for ~1.7 s. Reserves vs liabilities bars → **1 ms** → **SOLVENT** hanko. Then liabilities overflow: **INSOLVENT**. | "Every mint, swap and melt folds into one tiny proof." → "Anyone checks it against on-chain Bitcoin, in 1 ms." → "Fractional reserve? The proof fails. Publicly." | ticks, whoosh, thump, chime, glitch |
| 0:51.7–0:55.7 | **Numbers** | "Measured, not promised." **1 ms** · **~16 KB** · **−49.6%** · **0 sat**. | — | clinks |
| 0:55.7–1:01.2 | **Outro** | The crew pops in from the center out (7 in landscape, 5 in vertical). **Zashu** wordmark, "Cashu speed. Shinobi privacy.", `cargo run --release -p zashu-mint` → `localhost:8080/playground`. | — | ticks, thump, chime |

> **Numbers in the rendered video predate the current build.** The video shows a 16 KB solvency proof verified in 1 ms. Today the default Halo 2 proof is 3.4 KB, verified in about 2 ms, and the opt-in Ragu proof is 6.2 KB, verified in about 70 ms. Zashu supports both backends; a re-render should say so and use these figures.

A **Cashu-native · Shield · Stealth · Safety · Solvency** progress bar runs across the middle scenes.

## Music (`scripts/make-music.py`)

A calm ambient bed, synthesized from scratch in the **miyako-bushi** (in-sen) scale on D (D Eb G A Bb), at 80 BPM. No samples, no licensing. It is built to sit *under* the captions and SFX: no driving drums, soft attacks, and an even level throughout.

* **Throughout:** a warm, slowly breathing pad that cycles through four in-sen chords.
* **Hook / Title:** a few slow koto notes and a furin (wind-chime) shimmer.
* **Cashu-native / Shield:** a gentle quarter-note koto arpeggio over a whisper-quiet low pulse.
* **Stealth:** the pulse drops out. A sparse koto line and a soft shakuhachi phrase take over.
* **Safety / Solvency:** an eighth-note koto arpeggio for a little more motion, and the pulse returns.
* **Numbers:** a rising koto line.
* **Outro:** a chime, a descending koto cascade, and a long pad ring-out.

A small level envelope (`LEVELS` in the script) keeps sections within about ±2 dB of each other. The bed is normalized to −27 LUFS, and the composition plays it at volume 0.45.

## Rendering (`./video`)

```bash
cd video
pnpm install

pnpm run sfx          # (re)generate SFX + the music bed
pnpm run dev          # Remotion Studio preview
pnpm run render:16x9  # → out/zashu-demo-16x9.mp4 (loudness-mastered to -16 LUFS)
pnpm run render:9x16  # → out/zashu-demo-9x16.mp4
```

* **Your own music:** put a track at `video/public/bgm.mp3`. It replaces the synthesized bed automatically.
* **Mascots:** the video uses the transparent PNGs in `video/public/assets/transparent/`, copied from `assets/transparent/`. Re-copy them when a variant changes.
* **Timing:** scene lengths live in `SCENES` in `src/ZashuDemo.tsx`. Beat timings live in constants exported by each scene (`COMPAT`, `SHIELD_SLASH`, `STEALTH`, `AUDIT`, …), and the SFX cues read the same constants. The music's section times are at the top of `scripts/make-music.py`. Keep them in step if you retime scenes.
