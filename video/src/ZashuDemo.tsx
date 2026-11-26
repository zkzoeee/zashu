import React from "react";
import {
  AbsoluteFill,
  Audio,
  Sequence,
  getStaticFiles,
  interpolate,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { SakuraLayer } from "./components/SakuraLayer";
import { C, FONT, rgba, useLayout } from "./theme";
import { Hook } from "./scenes/Hook";
import { TitleDrop } from "./scenes/TitleDrop";
import { COMPAT, Compat } from "./scenes/Compat";
import { SHIELD_SLASH, Shield } from "./scenes/Shield";
import { STEALTH, Stealth } from "./scenes/Stealth";
import { BLOCK_HIT, Blocked } from "./scenes/Blocked";
import { AUDIT, Audit } from "./scenes/Audit";
import { NUMBERS_STEP, Numbers } from "./scenes/Numbers";
import { OUTRO_CREW_STEP, OUTRO_TYPE_AT, Outro } from "./scenes/Outro";

/**
 * Timeline (30 fps). Scene lengths are in frames.
 * Hook → Title → Compat → Shield → Stealth → Blocked → Audit → Numbers → Outro
 */
const SCENES = [
  { id: "hook", len: 150, C: Hook },
  { id: "title", len: 105, C: TitleDrop },
  { id: "compat", len: 240, C: Compat, chapter: "Cashu-native" },
  { id: "shield", len: 300, C: Shield, chapter: "Shield" },
  { id: "stealth", len: 300, C: Stealth, chapter: "Stealth" },
  { id: "blocked", len: 135, C: Blocked, chapter: "Safety" },
  { id: "audit", len: 321, C: Audit, chapter: "Solvency" },
  { id: "numbers", len: 120, C: Numbers },
  { id: "outro", len: 165, C: Outro },
] as const;

const starts: Record<string, number> = {};
let acc = 0;
for (const s of SCENES) {
  starts[s.id] = acc;
  acc += s.len;
}
export const TOTAL_FRAMES = acc; // 1836 = 61.2 s

type Cue = { at: number; sfx: string; vol?: number };
const S = starts;
const CUES: Cue[] = [
  // hook
  { at: S.hook + 0, sfx: "thump", vol: 0.7 },
  { at: S.hook + 14, sfx: "whoosh", vol: 0.9 },
  { at: S.hook + 62, sfx: "tick" },
  { at: S.hook + 80, sfx: "tick" },
  { at: S.hook + 98, sfx: "tick" },
  // title
  { at: S.title - 2, sfx: "shing", vol: 0.5 },
  { at: S.title + 14, sfx: "thump" },
  // compat
  { at: S.compat + 10, sfx: "tick" },
  { at: S.compat + 20, sfx: "tick" },
  { at: S.compat + COMPAT.shieldStart, sfx: "whoosh", vol: 0.9 },
  { at: S.compat + COMPAT.shieldEnd, sfx: "clink" },
  { at: S.compat + COMPAT.unshieldStart, sfx: "whoosh", vol: 0.9 },
  { at: S.compat + COMPAT.unshieldEnd, sfx: "clink" },
  { at: S.compat + COMPAT.shared, sfx: "thump", vol: 0.6 },
  { at: S.compat + COMPAT.shared + 8, sfx: "chime", vol: 0.6 },
  // shield
  { at: S.shield + 6, sfx: "clink" },
  { at: S.shield + 16, sfx: "clink" },
  { at: S.shield + 26, sfx: "clink" },
  { at: S.shield + 70, sfx: "buzz", vol: 0.5 },
  { at: S.shield + SHIELD_SLASH, sfx: "shing", vol: 0.55 },
  { at: S.shield + SHIELD_SLASH + 10, sfx: "thump", vol: 0.8 },
  { at: S.shield + 175, sfx: "tick" },
  { at: S.shield + 181, sfx: "tick" },
  { at: S.shield + 187, sfx: "tick" },
  // stealth
  { at: S.stealth + STEALTH.sendStart, sfx: "whoosh", vol: 1 },
  { at: S.stealth + STEALTH.atMint + 4, sfx: "tick" },
  { at: S.stealth + STEALTH.atMint + 12, sfx: "tick" },
  { at: S.stealth + STEALTH.atMint + 20, sfx: "tick" },
  { at: S.stealth + STEALTH.atMint + 28, sfx: "tick" },
  { at: S.stealth + STEALTH.atMint + 36, sfx: "tick" },
  { at: S.stealth + STEALTH.deliverStart, sfx: "whoosh", vol: 1 },
  { at: S.stealth + STEALTH.delivered, sfx: "chime", vol: 0.9 },
  // blocked
  { at: S.blocked + 10, sfx: "whoosh", vol: 1 },
  { at: S.blocked + BLOCK_HIT, sfx: "thump" },
  { at: S.blocked + BLOCK_HIT, sfx: "glitch", vol: 0.6 },
  { at: S.blocked + BLOCK_HIT + 2, sfx: "shing", vol: 0.35 },
  // audit
  ...Array.from({ length: 8 }, (_, i) => ({ at: S.audit + 8 + i * 5, sfx: "tick", vol: 0.6 })),
  { at: S.audit + AUDIT.fold, sfx: "whoosh", vol: 0.6 },
  { at: S.audit + AUDIT.folded, sfx: "chime", vol: 0.45 },
  { at: S.audit + AUDIT.verified, sfx: "tick" },
  { at: S.audit + AUDIT.stamp, sfx: "thump" },
  { at: S.audit + AUDIT.stamp + 2, sfx: "chime", vol: 0.6 },
  { at: S.audit + AUDIT.cheat, sfx: "glitch", vol: 0.7 },
  { at: S.audit + AUDIT.cheat + 10, sfx: "thump" },
  { at: S.audit + AUDIT.cheat + 10, sfx: "buzz", vol: 0.6 },
  // numbers
  ...Array.from({ length: 4 }, (_, i) => ({ at: S.numbers + 6 + i * NUMBERS_STEP, sfx: "clink", vol: 0.6 })),
  // outro
  ...Array.from({ length: 5 }, (_, i) => ({ at: S.outro + i * OUTRO_CREW_STEP, sfx: "tick", vol: 0.8 })),
  { at: S.outro + 18, sfx: "thump" },
  { at: S.outro + 18, sfx: "shing", vol: 0.35 },
  { at: S.outro + OUTRO_TYPE_AT + 32, sfx: "chime", vol: 0.7 },
];

const SFX_GAIN = 0.6; // headroom: stacked hits otherwise clip. scripts/master.sh normalizes loudness.
const SFX_LEN: Record<string, number> = { whoosh: 18, shing: 27, thump: 21, clink: 9, chime: 42, glitch: 12, tick: 2, buzz: 15 };

const hasFile = (name: string) => getStaticFiles().some((f) => f.name === name);

export const ZashuDemo: React.FC = () => {
  const userTrack = hasFile("bgm.mp3");
  return (
    <AbsoluteFill
      style={{
        background: `radial-gradient(circle at 78% 12%, ${rgba(C.violet, 0.14)}, transparent 45%), radial-gradient(circle at 15% 90%, ${rgba(C.orange, 0.06)}, transparent 40%), ${C.bg}`,
        color: C.text,
        fontFamily: FONT,
      }}
    >
      <SakuraLayer opacity={0.35} />

      {SCENES.map((s) => (
        <Sequence key={s.id} from={starts[s.id]} durationInFrames={s.len} name={s.id}>
          <s.C />
        </Sequence>
      ))}

      <ChapterBar />

      {/* Music: your own bgm.mp3 if present, else the synthesized bed */}
      <Audio
        src={staticFile(userTrack ? "bgm.mp3" : "sfx/bed.mp3")}
        volume={(f) =>
          0.45 *  // music sits well under captions + SFX
          interpolate(f, [TOTAL_FRAMES - 45, TOTAL_FRAMES], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" })
        }
      />
      {CUES.map((c, i) => (
        <Sequence key={i} from={c.at} durationInFrames={SFX_LEN[c.sfx] + 4} name={`sfx:${c.sfx}`}>
          <Audio src={staticFile(`sfx/${c.sfx}.wav`)} volume={SFX_GAIN * (c.vol ?? 1)} />
        </Sequence>
      ))}
    </AbsoluteFill>
  );
};

/** Chapter progress indicator shown during the Cashu-native + feature scenes. */
const ChapterBar: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const { width } = useVideoConfig();
  const chapters = SCENES.filter((s) => "chapter" in s) as unknown as { id: string; len: number; chapter: string }[];
  const first = starts[chapters[0].id];
  const last = starts[chapters[chapters.length - 1].id] + chapters[chapters.length - 1].len;
  if (frame < first - 10 || frame > last + 10) return null;
  const vis = Math.min(
    interpolate(frame, [first - 10, first + 5], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
    interpolate(frame, [last - 5, last + 10], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
  );
  const barW = vertical ? width - 120 : 860;
  return (
    <div
      style={{
        position: "absolute",
        top: vertical ? 70 : 78,
        right: vertical ? 60 : 90,
        width: barW,
        display: "flex",
        gap: 10,
        opacity: vis,
      }}
    >
      {chapters.map((c) => {
        const st = starts[c.id];
        const p = interpolate(frame, [st, st + c.len], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
        const active = frame >= st && frame < st + c.len;
        return (
          <div key={c.id} style={{ flex: 1 }}>
            <div style={{ height: 6, borderRadius: 3, background: C.line, overflow: "hidden" }}>
              <div style={{ width: `${p * 100}%`, height: "100%", background: active ? C.violet : C.violetHi }} />
            </div>
            <div
              style={{
                marginTop: 8,
                fontSize: 19,
                fontWeight: 700,
                letterSpacing: "0.05em",
                whiteSpace: "nowrap",
                textTransform: "uppercase",
                color: active ? C.text : C.dim,
              }}
            >
              {c.chapter}
            </div>
          </div>
        );
      })}
    </div>
  );
};
