#!/usr/bin/env python3
"""Generate crisp, full-resolution (1024x1024) transparent PNGs of all Zashi mascots.

Pipeline:
1. Median border background estimation (navy ~#0D111C).
2. Tight background flood-fill from image borders (stops dead at black outlines).
3. Connected-component removal of the disconnected bottom drop shadow & JPEG specks.
4. Exterior glow un-mixing (flood-fills outward-facing soft glows around scrolls,
   lanterns, prisms, flames, and petals without crossing black outlines or solid fills,
   converting dark-navy-blended halos into pure translucent color with smooth alpha).
5. 1px outer-edge anti-aliasing on crisp black outlines.
"""
import math
import pathlib
import subprocess
import sys
from collections import deque


def process_image(src: pathlib.Path, dst: pathlib.Path) -> None:
    w = h = 1024
    raw = subprocess.run(
        ["ffmpeg", "-v", "error", "-i", str(src), "-f", "rawvideo", "-pix_fmt", "rgb24", "-"],
        check=True,
        capture_output=True,
    ).stdout
    if len(raw) != w * h * 3:
        raise RuntimeError(f"Unexpected size for {src}: {len(raw)}")

    # 1. Sample background median from 4px border strips
    rs, gs, bs = [], [], []
    for y in range(h):
        for x in (0, 1, 2, 3, w - 4, w - 3, w - 2, w - 1):
            j = (y * w + x) * 3
            rs.append(raw[j]); gs.append(raw[j + 1]); bs.append(raw[j + 2])
    for x in range(w):
        for y in (0, 1, 2, 3, h - 4, h - 3, h - 2, h - 1):
            j = (y * w + x) * 3
            rs.append(raw[j]); gs.append(raw[j + 1]); bs.append(raw[j + 2])
    rs.sort(); gs.sort(); bs.sort()
    bg_r = rs[len(rs) // 2]
    bg_g = gs[len(gs) // 2]
    bg_b = bs[len(bs) // 2]

    # 2. Tight flood-fill of flat navy background from borders
    # Never penetrates black outlines (which have b < bg_b - 9).
    bg_mask = bytearray(w * h)
    q = deque()
    for x in range(w):
        q.append(x)
        q.append((h - 1) * w + x)
    for y in range(1, h - 1):
        q.append(y * w)
        q.append(y * w + w - 1)

    max_dist_sq = 14 * 14
    min_bg_b = max(14, bg_b - 9)

    while q:
        i = q.popleft()
        if bg_mask[i]:
            continue
        j = i * 3
        r, g, b = raw[j], raw[j + 1], raw[j + 2]
        dr = r - bg_r
        dg = g - bg_g
        db = b - bg_b
        if dr * dr + dg * dg + db * db <= max_dist_sq and b >= min_bg_b:
            bg_mask[i] = 1
            x = i % w
            y = i // w
            if x > 0 and not bg_mask[i - 1]: q.append(i - 1)
            if x < w - 1 and not bg_mask[i + 1]: q.append(i + 1)
            if y > 0 and not bg_mask[i - w]: q.append(i - w)
            if y < h - 1 and not bg_mask[i + w]: q.append(i + w)

    # 3. Remove disconnected bottom drop shadow & tiny dark JPEG specks
    visited = bytearray(w * h)
    for idx in range(w * h):
        if bg_mask[idx] or visited[idx]:
            continue
        comp = []
        cq = deque([idx])
        visited[idx] = 1
        min_y = h
        max_lum = 0
        while cq:
            c = cq.popleft()
            comp.append(c)
            y = c // w
            x = c % w
            if y < min_y: min_y = y
            j = c * 3
            lum = max(raw[j], raw[j + 1], raw[j + 2])
            if lum > max_lum: max_lum = lum
            if x > 0 and not bg_mask[c - 1] and not visited[c - 1]:
                visited[c - 1] = 1; cq.append(c - 1)
            if x < w - 1 and not bg_mask[c + 1] and not visited[c + 1]:
                visited[c + 1] = 1; cq.append(c + 1)
            if y > 0 and not bg_mask[c - w] and not visited[c - w]:
                visited[c - w] = 1; cq.append(c - w)
            if y < h - 1 and not bg_mask[c + w] and not visited[c + w]:
                visited[c + w] = 1; cq.append(c + w)

        if (min_y > 820 and max_lum < 55) or (len(comp) < 12 and max_lum < 60):
            for c in comp:
                bg_mask[c] = 1

    # 4. Exterior soft-glow un-mixing!
    # Flood-fill from background into soft-glow halo pixels that are brighter than bg
    # (additive purple/pink/amber glow on dark navy) without crossing black outlines,
    # cool navy/slate clothing, or solid bright fills.
    glow_mask = bytearray(w * h)
    gq = deque()
    for i in range(w * h):
        if bg_mask[i]:
            continue
        x = i % w
        y = i // w
        touches_bg = (
            (x > 0 and bg_mask[i - 1])
            or (x < w - 1 and bg_mask[i + 1])
            or (y > 0 and bg_mask[i - w])
            or (y < h - 1 and bg_mask[i + w])
        )
        if touches_bg:
            gq.append((i, 1))

    GLOW_MAX = 115  # excess channel above bg where glow becomes 100% opaque
    MAX_GLOW_DEPTH = 95
    while gq:
        i, depth = gq.popleft()
        if bg_mask[i] or glow_mask[i] or depth > MAX_GLOW_DEPTH:
            continue
        j = i * 3
        r, g, b = raw[j], raw[j + 1], raw[j + 2]
        # Stop at black outlines (darker than bg)
        if max(r, g, b) < 22 or b < bg_b - 8:
            continue
        # Excess above background
        er = r - bg_r
        eg = g - bg_g
        eb = b - bg_b
        # Must be an additive glow (not significantly darker than bg in any channel)
        if er < -10 or eg < -10 or eb < -10:
            continue
        strength = max(er, eg, eb)
        # Stop at solid bright objects (flame core, crystal facets, scroll body, petals)
        if strength >= GLOW_MAX:
            continue
        # Chroma guard: real glows are purple/pink (er > eg) or warm amber (er > eb).
        # Cool navy/slate clothing (monk jacket, tachyon suit) has eg >= er and is excluded.
        is_purple_glow = (er > eg + 4) and (eb > eg + 6)
        is_amber_glow = (er > eb + 6) and (er > 4)
        is_faint_outer_edge = (depth <= 12) and (strength < 26)
        if not (is_purple_glow or is_amber_glow or is_faint_outer_edge):
            continue
        glow_mask[i] = 1
        x = i % w
        y = i // w
        nd = depth + 1
        if x > 0 and not bg_mask[i - 1] and not glow_mask[i - 1]: gq.append((i - 1, nd))
        if x < w - 1 and not bg_mask[i + 1] and not glow_mask[i + 1]: gq.append((i + 1, nd))
        if y > 0 and not bg_mask[i - w] and not glow_mask[i - w]: gq.append((i - w, nd))
        if y < h - 1 and not bg_mask[i + w] and not glow_mask[i + w]: gq.append((i + w, nd))

    # 5. Build RGBA with soft un-premultiplied glows and 1px crisp AA on solid outlines
    alpha = bytearray(w * h)
    out_rgb = bytearray(raw)

    for i in range(w * h):
        j = i * 3
        if bg_mask[i]:
            alpha[i] = 0
            out_rgb[j] = 0; out_rgb[j + 1] = 0; out_rgb[j + 2] = 0
        elif glow_mask[i]:
            r, g, b = raw[j], raw[j + 1], raw[j + 2]
            er = max(0, r - bg_r)
            eg = max(0, g - bg_g)
            eb = max(0, b - bg_b)
            strength = max(er, eg, eb)
            # Smooth translucent alpha ramp with gentle feathering to 0
            t = max(0.0, min(1.0, (strength - 6.0) / (GLOW_MAX - 6.0)))
            a = t ** 1.35
            ai = int(round(a * 255))
            alpha[i] = ai
            if ai > 0:
                # Un-mix navy background so glow stays pure bright color on light & dark bgs
                inv = 1.0 / max(a, 0.15)
                out_rgb[j] = min(255, int(round(er * inv)))
                out_rgb[j + 1] = min(255, int(round(eg * inv)))
                out_rgb[j + 2] = min(255, int(round(eb * inv)))
            else:
                out_rgb[j] = 0; out_rgb[j + 1] = 0; out_rgb[j + 2] = 0
        else:
            alpha[i] = 255
            # Subtle 1px anti-aliasing on solid pixels directly touching pure background
            x = i % w
            y = i // w
            bg_neighbors = (
                (1 if x > 0 and bg_mask[i - 1] else 0)
                + (1 if x < w - 1 and bg_mask[i + 1] else 0)
                + (1 if y > 0 and bg_mask[i - w] else 0)
                + (1 if y < h - 1 and bg_mask[i + w] else 0)
            )
            if bg_neighbors > 0:
                r, g, b = raw[j], raw[j + 1], raw[j + 2]
                cd = math.sqrt((r - bg_r) ** 2 + (g - bg_g) ** 2 + (b - bg_b) ** 2)
                if cd < 22 and b >= bg_b - 7:
                    alpha[i] = int(round(max(0.0, min(1.0, (cd - 10.0) / 12.0)) * 255))
                elif bg_neighbors >= 2:
                    alpha[i] = 195
                else:
                    alpha[i] = 225

    rgba = bytearray(w * h * 4)
    rgba[0::4] = out_rgb[0::3]
    rgba[1::4] = out_rgb[1::3]
    rgba[2::4] = out_rgb[2::3]
    rgba[3::4] = alpha

    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "ffmpeg", "-v", "error", "-y",
            "-f", "rawvideo", "-pix_fmt", "rgba", "-s", f"{w}x{h}", "-i", "-",
            "-compression_level", "9",
            str(dst),
        ],
        input=bytes(rgba),
        check=True,
    )
    print(f"OK {dst.name} (bg=({bg_r},{bg_g},{bg_b}))")


def main() -> None:
    src_dir = pathlib.Path(sys.argv[1])
    dst_dir = pathlib.Path(sys.argv[2])
    for p in sorted(src_dir.glob("zashi-*.jpg")):
        process_image(p, dst_dir / f"{p.stem}.png")


if __name__ == "__main__":
    main()
