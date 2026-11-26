#!/usr/bin/env python3
"""Synthesize a calm, ambient Japanese-flavoured music bed (stdlib + ffmpeg only).

Meant to sit *under* captions and SFX, not compete with them: no driving drums,
soft attacks, steady level from start to finish.

Instruments, all generated from scratch (no samples, no licensing):
  * pad          - warm, slowly breathing chord (detuned sines, slow attack/release)
  * koto         - soft Karplus-Strong plucks, mostly gentle arpeggios
  * shakuhachi   - breathy flute phrases, sparse
  * furin        - glass wind-chime sparkles at scene changes
  * pulse        - a very quiet low heartbeat (soft kick) in the middle sections

Scale: miyako-bushi (in-sen) on D: D Eb G A Bb.  Tempo 80 BPM.
Sections line up with the scenes in src/ZashuDemo.tsx (61.2 s).
Output: public/sfx/bed.mp3 (loudness-normalized to TARGET_LUFS)
"""
import json
import math
import pathlib
import random
import struct
import subprocess

SR = 44100
DUR = 61.2
N = int(SR * DUR)
BEAT = 0.75  # 80 BPM
BAR = 4 * BEAT
TARGET_LUFS = -27
ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "public" / "sfx" / "bed.mp3"

# Scene boundaries (seconds) — keep in sync with SCENES in src/ZashuDemo.tsx
HOOK, TITLE, COMPAT, SHIELD, STEALTH, BLOCKED, AUDIT, NUMBERS, OUTRO = (
    0.0, 5.0, 8.5, 16.5, 26.5, 36.5, 41.0, 51.7, 55.7)

random.seed(7)
mix = [0.0] * N

NOTE = {
    "G2": 98.00, "A2": 110.00, "Bb2": 116.54,
    "D3": 146.83, "Eb3": 155.56, "G3": 196.00, "A3": 220.00, "Bb3": 233.08,
    "D4": 293.66, "Eb4": 311.13, "G4": 392.00, "A4": 440.00, "Bb4": 466.16,
    "D5": 587.33, "Eb5": 622.25, "G5": 783.99, "A5": 880.00, "Bb5": 932.33, "D6": 1174.66,
}

# Four-chord cycle (one chord per bar), all from the in-sen scale
CHORDS = [
    ["D3", "A3", "D4", "Eb4"],
    ["Bb2", "G3", "D4", "A4"],
    ["G2", "D3", "A3", "Bb3"],
    ["A2", "Eb3", "A3", "D4"],
]


def add(buf, t, gain=1.0):
    start = int(t * SR)
    if start >= N:
        return
    end = min(N, start + len(buf))
    for i in range(start, end):
        mix[i] += buf[i - start] * gain


_cache = {}


def pluck(freq, length=2.4, decay=0.998, bright=0.3):
    """Soft Karplus-Strong string (koto), cached per pitch."""
    key = ("pluck", round(freq, 2), length, decay, bright)
    if key in _cache:
        return _cache[key]
    n = int(SR * length)
    p = max(2, int(SR / freq))
    rnd = random.Random(int(freq * 100))
    ring = [rnd.uniform(-1, 1) for _ in range(p)]
    for _ in range(int((1 - bright) * 5)):  # softer pick = smoother excitation
        ring = [(ring[i] + ring[i - 1]) * 0.5 for i in range(p)]
    out = [0.0] * n
    idx = 0
    for i in range(n):
        a = ring[idx]
        v = decay * 0.5 * (a + ring[(idx + 1) % p])
        ring[idx] = v
        out[i] = a
        idx = (idx + 1) % p
    att = int(0.004 * SR)  # tiny attack: no click
    for i in range(att):
        out[i] *= i / att
    f = int(0.05 * SR)
    for i in range(f):
        out[n - 1 - i] *= i / f
    _cache[key] = out
    return out


def koto(name, length=2.4):
    return pluck(NOTE[name], length)


def pad_chord(names, t0, length, gain):
    """Warm pad: each note = 3 slightly detuned sines + a quiet octave, slow swell."""
    start = int(t0 * SR)
    n = int(length * SR)
    att, rel = 1.2, 1.4
    freqs = [NOTE[x] for x in names]
    for i in range(n):
        idx = start + i
        if idx >= N:
            break
        t = i / SR
        env = min(1.0, t / att, (length - t) / rel)
        if env <= 0:
            continue
        env = env * env * (3 - 2 * env)  # smoothstep
        breathe = 0.85 + 0.15 * math.sin(2 * math.pi * 0.18 * (t0 + t))
        s = 0.0
        for f in freqs:
            s += (math.sin(2 * math.pi * f * 0.997 * t) + math.sin(2 * math.pi * f * t)
                  + math.sin(2 * math.pi * f * 1.003 * t)) / 3 + 0.12 * math.sin(2 * math.pi * f * 2 * t)
        mix[idx] += gain * env * breathe * s / len(freqs)


def furin(t, gain=0.08):
    """Glass wind chime: a few inharmonic partials, long shimmer."""
    key = "furin"
    if key not in _cache:
        n = int(SR * 2.5)
        partials = [(2093, 1.0), (5650, 0.35), (8470, 0.15), (3140, 0.25)]
        out = [0.0] * n
        for i in range(n):
            tt = i / SR
            out[i] = sum(a * math.sin(2 * math.pi * f * tt) * math.exp(-tt * (2.2 + f / 4000)) for f, a in partials)
        _cache[key] = out
    add(_cache[key], t, gain)
    add(_cache[key], t + 0.17, gain * 0.5)


def soft_kick():
    if "kick" in _cache:
        return _cache["kick"]
    n = int(SR * 0.5)
    out = [0.0] * n
    ph = 0.0
    for i in range(n):
        tt = i / SR
        f = 48 + 40 * math.exp(-tt * 25)
        ph += 2 * math.pi * f / SR
        out[i] = math.sin(ph) * math.exp(-tt * 7) * min(1, tt / 0.006)
    _cache["kick"] = out
    return out


def shakuhachi(name, length):
    f = NOTE[name]
    n = int(SR * length)
    rnd = random.Random(int(f))
    out = [0.0] * n
    phase = bp1 = bp2 = 0.0
    for i in range(n):
        t = i / SR
        vib = 0.0 if t < 0.5 else 0.008 * min(1, (t - 0.5) * 1.5) * math.sin(2 * math.pi * 4.8 * t)
        sc = -0.03 * math.exp(-t * 7)
        phase += 2 * math.pi * f * (1 + vib + sc) / SR
        tone = math.sin(phase) + 0.12 * math.sin(2 * phase)
        w = rnd.uniform(-1, 1)
        bp1 += 0.2 * (w - bp1)
        bp2 += 0.2 * (bp1 - bp2)
        env = min(1, t / 0.35) * min(1, (length - t) / 0.6)
        out[i] = env * (0.8 * tone + 0.9 * (bp1 - bp2) * (0.4 + 0.6 * math.exp(-t * 2)))
    return out


# ---------------------------------------------------------------- arrangement
# Pad: one chord per bar for the whole piece (bars overlap a little for smooth changes)
t = 0.0
b = 0
while t < DUR:
    pad_chord(CHORDS[b % 4], t, BAR + 1.2, 0.055)
    t += BAR
    b += 1


def chord_at(t):
    return CHORDS[int(t // BAR) % 4]


def arpeggio(t0, t1, gain, step=BEAT / 2, up=True):
    """Gentle koto arpeggio over the current chord (plus an octave up)."""
    t = t0
    k = 0
    while t < t1:
        names = chord_at(t)
        hi = [n[:-1] + str(int(n[-1]) + 1) for n in names[1:]]
        seq = names[1:] + [h for h in hi if h in NOTE]
        if not up:
            seq = seq[::-1]
        note = seq[k % len(seq)]
        # occasional rest keeps it airy
        if k % 8 != 7:
            add(koto(note), t, gain * (1.0 if k % 4 == 0 else 0.75))
        t += step
        k += 1


# HOOK: pad + a few slow koto notes
for tt, n in [(0.4, "D5"), (1.9, "A4"), (3.1, "Eb5"), (4.2, "D5")]:
    add(koto(n, 3.0), tt, 0.16)
furin(0.2, 0.06)

# TITLE: chime swell, one soft low "bloom" (pad doubled), slow koto
furin(TITLE + 0.1, 0.09)
pad_chord(["D3", "A3", "D4"], TITLE, 3.5, 0.04)
for k, n in enumerate(["D4", "G4", "A4", "D5"]):
    add(koto(n, 3.0), TITLE + 0.2 + k * 0.28, 0.13)

# COMPAT + SHIELD: quarter-note arpeggio + whisper pulse
arpeggio(COMPAT, STEALTH, 0.11, step=BEAT)
for tt in [COMPAT + i * BEAT * 2 for i in range(int((STEALTH - COMPAT) / (BEAT * 2)))]:
    add(soft_kick(), tt, 0.10)
furin(SHIELD, 0.05)

# STEALTH: drop the pulse, shakuhachi sings over pad + sparse koto
furin(STEALTH, 0.06)
arpeggio(STEALTH, BLOCKED, 0.08, step=BEAT * 2, up=False)
add(shakuhachi("A4", 3.0), STEALTH + 0.8, 0.07)
add(shakuhachi("Bb4", 1.6), STEALTH + 4.2, 0.06)
add(shakuhachi("D5", 3.4), STEALTH + 6.0, 0.06)

# BLOCKED + AUDIT: eighth-note arpeggio for a bit more motion, pulse back
arpeggio(BLOCKED, NUMBERS, 0.09, step=BEAT / 2)
for tt in [BLOCKED + i * BEAT * 2 for i in range(int((NUMBERS - BLOCKED) / (BEAT * 2)))]:
    add(soft_kick(), tt, 0.10)
furin(AUDIT, 0.05)

# NUMBERS: rising koto line
for k, n in enumerate(["D4", "Eb4", "G4", "A4", "Bb4", "D5", "Eb5", "G5"]):
    add(koto(n), NUMBERS + 0.2 + k * 0.45, 0.11)

# OUTRO: chime, descending koto cascade, long pad ring-out
furin(OUTRO, 0.08)
for k, n in enumerate(["A5", "G5", "Eb5", "D5", "Bb4", "A4", "G4", "D4"]):
    add(koto(n, 3.2), OUTRO + 0.3 + k * 0.16, 0.12)
add(shakuhachi("D5", 3.2), OUTRO + 1.6, 0.03)
pad_chord(["D3", "A3", "D4", "A4"], OUTRO + 1.0, DUR - OUTRO - 1.0, 0.04)

# ---------------------------------------------------------------- master
# Small level envelope keeps busier sections from poking out (dB)
LEVELS = [(0.0, 0.0), (TITLE - 0.3, 0.0), (TITLE + 0.3, -4.0), (COMPAT - 0.3, -4.0), (COMPAT + 0.3, 0.0),
          (STEALTH - 0.5, 0.0), (STEALTH + 0.5, -6.5), (BLOCKED - 0.5, -6.5), (BLOCKED + 0.5, 0.0),
          (OUTRO, 0.0), (OUTRO + 1.0, -3.5), (DUR, -3.5)]


def level_db(t):
    for (t0, d0), (t1, d1) in zip(LEVELS, LEVELS[1:]):
        if t0 <= t <= t1:
            return d0 + (d1 - d0) * ((t - t0) / (t1 - t0) if t1 > t0 else 0)
    return LEVELS[-1][1]


env = [10 ** (level_db(i / SR) / 20) for i in range(0, N, 64)]
peak = max(abs(v) for v in mix) or 1.0
fade = int(3.0 * SR)
pcm = bytearray()
for i, v in enumerate(mix):
    g = env[i >> 6] * 0.7 / peak
    if i > N - fade:
        g *= (N - i) / fade
    pcm += struct.pack("<h", int(max(-1, min(1, v * g)) * 32767))

# Gentle room + high cut, then normalize to a fixed loudness (two-pass, linear).
ROOM = "aecho=0.8:0.7:90|170:0.25|0.15,lowpass=f=7000"
pre = subprocess.run(
    ["ffmpeg", "-hide_banner", "-f", "s16le", "-ar", str(SR), "-ac", "1", "-i", "-",
     "-af", f"{ROOM},loudnorm=I={TARGET_LUFS}:TP=-3:LRA=20:print_format=json", "-f", "null", "-"],
    input=bytes(pcm), capture_output=True, check=True,
).stderr.decode()
m = json.loads(pre[pre.rindex("{"):pre.rindex("}") + 1])
norm = (
    f"loudnorm=I={TARGET_LUFS}:TP=-3:LRA=20:measured_I={m['input_i']}:measured_TP={m['input_tp']}:"
    f"measured_LRA={m['input_lra']}:measured_thresh={m['input_thresh']}:offset={m['target_offset']}:linear=true"
)
OUT.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(
    ["ffmpeg", "-v", "error", "-y", "-f", "s16le", "-ar", str(SR), "-ac", "1", "-i", "-",
     "-af", f"{ROOM},{norm},aresample={SR}", "-ac", "2", "-c:a", "libmp3lame", "-q:a", "3", str(OUT)],
    input=bytes(pcm),
    check=True,
)
print("wrote", OUT.relative_to(ROOT))
