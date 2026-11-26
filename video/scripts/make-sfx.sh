#!/usr/bin/env bash
# Synthesizes the demo's sound effects with ffmpeg.
# No samples, no licensing: everything is generated from oscillators and noise.
# Output: public/sfx/*.wav
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=public/sfx
mkdir -p "$OUT"
FF="ffmpeg -v error -y"
SR=44100

# Soft air whoosh for scene transitions
$FF -f lavfi -i "anoisesrc=d=0.55:c=pink:a=0.6:r=$SR" \
  -af "bandpass=f=1400:t=h:w=1800,afade=t=in:d=0.22:curve=qsin,afade=t=out:st=0.22:d=0.33:curve=exp,volume=0.9" \
  "$OUT/whoosh.wav"

# Katana "shing": bright metallic partials + airy noise tail
$FF -f lavfi -i "aevalsrc='0.35*sin(2*PI*3150*t)*exp(-5*t)+0.25*sin(2*PI*4720*t)*exp(-7*t)+0.18*sin(2*PI*6280*t)*exp(-9*t)':d=0.9:s=$SR" \
    -f lavfi -i "anoisesrc=d=0.9:c=white:a=0.25:r=$SR" \
  -filter_complex "[1]highpass=f=5000,afade=t=out:st=0:d=0.35:curve=exp[n];[0][n]amix=inputs=2:normalize=0,afade=t=in:d=0.01,volume=1.1" \
  "$OUT/shing.wav"

# Hanko / taiko thump: pitch-dropping sine body
$FF -f lavfi -i "aevalsrc='0.95*sin(2*PI*(45*t+(120/18)*(1-exp(-18*t))))*exp(-7*t)':d=0.7:s=$SR" \
  -af "lowpass=f=900,volume=1.4" "$OUT/thump.wav"

# Coin clink
$FF -f lavfi -i "aevalsrc='0.4*sin(2*PI*2380*t)*exp(-22*t)+0.3*sin(2*PI*3560*t)*exp(-28*t)+0.2*sin(2*PI*5210*t)*exp(-35*t)':d=0.3:s=$SR" \
  "$OUT/clink.wav"

# Success chime (major triad, gentle)
$FF -f lavfi -i "aevalsrc='0.22*sin(2*PI*880*t)*exp(-3*t)+0.18*sin(2*PI*1108.7*t)*exp(-3*(t-0.07))*gte(t,0.07)+0.16*sin(2*PI*1318.5*t)*exp(-3*(t-0.14))*gte(t,0.14)':d=1.4:s=$SR" \
  "$OUT/chime.wav"

# Digital glitch buzz
$FF -f lavfi -i "aevalsrc='0.32*sgn(sin(2*PI*(90+60*sgn(sin(2*PI*23*t)))*t))*gt(sin(2*PI*31*t),-0.2)':d=0.4:s=$SR" \
  -af "lowpass=f=3200,afade=t=out:st=0.25:d=0.15" "$OUT/glitch.wav"

# Tiny UI tick
$FF -f lavfi -i "aevalsrc='0.35*sin(2*PI*1900*t)*exp(-90*t)':d=0.06:s=$SR" "$OUT/tick.wav"

# Error buzz (low, short)
$FF -f lavfi -i "aevalsrc='0.4*sin(2*PI*110*t)*sgn(sin(2*PI*110*t))*exp(-4*t)+0.25*sin(2*PI*116*t)*exp(-4*t)':d=0.5:s=$SR" \
  -af "lowpass=f=1500" "$OUT/buzz.wav"

# The music bed (bed.mp3) is made by scripts/make-music.py.

ls -la "$OUT"
