import React from "react";
import {
  AbsoluteFill,
  Img,
  interpolate,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { C, MONO, rgba, useLayout } from "../theme";

/** Fades/zooms a whole scene in and out so cuts feel like transitions. */
export const SceneShell: React.FC<{ children: React.ReactNode; fadeOut?: boolean }> = ({
  children,
  fadeOut = true,
}) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const inP = interpolate(frame, [0, 8], [0, 1], { extrapolateRight: "clamp" });
  const outP = fadeOut
    ? interpolate(frame, [durationInFrames - 8, durationInFrames], [1, 0], {
        extrapolateLeft: "clamp",
      })
    : 1;
  const scale = interpolate(inP, [0, 1], [1.04, 1]) * interpolate(outP, [0, 1], [0.97, 1]);
  return (
    <AbsoluteFill
      style={{
        opacity: Math.min(inP, outP),
        transform: `scale(${scale})`,
        filter: `blur(${(1 - Math.min(inP, outP)) * 8}px)`,
      }}
    >
      {children}
    </AbsoluteFill>
  );
};

/** Spring that starts at `delay` frames. */
export const useSpring = (delay = 0, config = { damping: 14, stiffness: 160 }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({ frame: frame - delay, fps, config });
};

/**
 * Big burned-in caption (videos autoplay muted). Words pop in one by one.
 * `at` is the start frame; `until` hides it again.
 */
export const Caption: React.FC<{
  text: string;
  at?: number;
  until?: number;
  accent?: string[];
}> = ({ text, at = 0, until = Infinity, accent = [] }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { vertical } = useLayout();
  if (frame < at || frame >= until) return null;
  const words = text.split(" ");
  const out = until === Infinity ? 1 : interpolate(frame, [until - 6, until], [1, 0], { extrapolateLeft: "clamp" });
  return (
    <div
      style={{
        position: "absolute",
        left: 0,
        right: 0,
        bottom: vertical ? 220 : 70,
        display: "flex",
        justifyContent: "center",
        padding: "0 60px",
        opacity: out,
      }}
    >
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "center",
          gap: "0 0.28em",
          maxWidth: vertical ? 940 : 1500,
          fontSize: vertical ? 54 : 50,
          fontWeight: 800,
          letterSpacing: "-0.02em",
          lineHeight: 1.18,
          textAlign: "center",
          textShadow: "0 4px 24px rgba(0,0,0,0.9)",
        }}
      >
        {words.map((w, i) => {
          const s = spring({ frame: frame - at - i * 2.2, fps, config: { damping: 18, stiffness: 220 } });
          const clean = w.replace(/[.,!?—]/g, "");
          return (
            <span
              key={i}
              style={{
                display: "inline-block",
                opacity: s,
                transform: `translateY(${(1 - s) * 18}px)`,
                color: accent.includes(clean) ? C.violetHi : C.text,
              }}
            >
              {w}
            </span>
          );
        })}
      </div>
    </div>
  );
};

/** Small top-left label naming the feature / spec. */
export const Kicker: React.FC<{ spec: string; title: string; color?: string }> = ({
  spec,
  title,
  color = C.violet,
}) => {
  const s = useSpring(4);
  const { vertical } = useLayout();
  return (
    <div
      style={{
        position: "absolute",
        top: vertical ? 150 : 70,
        left: vertical ? 0 : 90,
        right: vertical ? 0 : undefined,
        display: "flex",
        justifyContent: vertical ? "center" : "flex-start",
        alignItems: "center",
        gap: 16,
        opacity: s,
        transform: `translateX(${(1 - s) * -30}px)`,
      }}
    >
      <span
        style={{
          fontFamily: MONO,
          fontSize: 22,
          fontWeight: 700,
          color,
          border: `2px solid ${color}`,
          background: rgba(color, 0.12),
          borderRadius: 8,
          padding: "6px 12px",
        }}
      >
        {spec}
      </span>
      <span style={{ fontSize: 34, fontWeight: 800, color: C.text, letterSpacing: "-0.01em" }}>{title}</span>
    </div>
  );
};

/** Mascot from the transparent PNGs in public/assets/transparent (copied from ../assets/transparent). */
export const Mascot: React.FC<{ file: string; size: number; style?: React.CSSProperties }> = ({
  file,
  size,
  style,
}) => (
  <Img
    src={staticFile(`assets/transparent/${file.replace(/\.jpg$/, ".png")}`)}
    style={{
      width: size,
      height: size,
      ...style,
    }}
  />
);

export const Chip: React.FC<{ children: React.ReactNode; color?: string; delay?: number; size?: number }> = ({
  children,
  color = C.violetHi,
  delay = 0,
  size = 26,
}) => {
  const s = useSpring(delay, { damping: 12, stiffness: 200 });
  return (
    <div
      style={{
        fontSize: size,
        fontWeight: 700,
        color,
        border: `2px solid ${rgba(color, 0.55)}`,
        background: rgba(color, 0.1),
        padding: "10px 22px",
        borderRadius: 999,
        transform: `scale(${s})`,
        opacity: s,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </div>
  );
};

/** Diagonal katana slash streak. */
export const Slash: React.FC<{ at: number; color?: string; angle?: number }> = ({
  at,
  color = C.violet,
  angle = -14,
}) => {
  const frame = useCurrentFrame();
  const p = interpolate(frame, [at, at + 7], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const fade = interpolate(frame, [at + 7, at + 16], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  if (frame < at || frame > at + 16) return null;
  return (
    <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", pointerEvents: "none" }}>
      <div
        style={{
          width: "160%",
          height: 10,
          transform: `rotate(${angle}deg) scaleX(${p})`,
          transformOrigin: "left center",
          background: `linear-gradient(90deg, transparent, ${color} 30%, #fff 60%, ${C.orange} 85%, transparent)`,
          boxShadow: `0 0 40px ${color}, 0 0 90px ${rgba(color, 0.6)}`,
          opacity: fade,
          borderRadius: 10,
        }}
      />
    </AbsoluteFill>
  );
};

/** Full-frame flash, e.g. on impacts. */
export const Flash: React.FC<{ at: number; color?: string; len?: number; max?: number }> = ({
  at,
  color = "#ffffff",
  len = 10,
  max = 0.35,
}) => {
  const frame = useCurrentFrame();
  const o = interpolate(frame, [at, at + 1, at + len], [0, max, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  return <AbsoluteFill style={{ background: color, opacity: o, pointerEvents: "none" }} />;
};

/** Deterministic camera shake starting at `at`. */
export const useShake = (at: number, len = 12, amp = 14) => {
  const frame = useCurrentFrame();
  const t = frame - at;
  if (t < 0 || t > len) return "translate(0px,0px)";
  const k = (1 - t / len) * amp;
  return `translate(${Math.sin(t * 2.7) * k}px, ${Math.cos(t * 3.3) * k}px)`;
};
