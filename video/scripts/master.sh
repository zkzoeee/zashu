#!/usr/bin/env bash
# Loudness-normalize a rendered MP4 for social platforms (-16 LUFS, -1 dBTP).
# Two-pass loudnorm; the video stream is copied untouched.
set -euo pipefail
in="$1"
tmp="${in%.mp4}.mastering.mp4"
stats=$(ffmpeg -hide_banner -i "$in" -af loudnorm=I=-16:TP=-1:LRA=11:print_format=json -f null - 2>&1 | sed -n '/^{/,/^}/p')
get() { echo "$stats" | grep "\"$1\"" | sed -E 's/.*: "([^"]+)".*/\1/'; }
ffmpeg -v error -y -i "$in" -c:v copy \
  -af "loudnorm=I=-16:TP=-1:LRA=11:measured_I=$(get input_i):measured_TP=$(get input_tp):measured_LRA=$(get input_lra):measured_thresh=$(get input_thresh):offset=$(get target_offset):linear=true,aresample=48000" \
  -c:a aac -b:a 192k "$tmp"
mv "$tmp" "$in"
echo "mastered $in"
