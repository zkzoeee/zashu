import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame, Easing } from "remotion";
import { C, glow, rgba, useLayout } from "../theme";
import { SceneShell, useSpring } from "../components/ui";

// All figures come from BENCHMARKS.md / the NUTZ specs.
const STATS = [
  { to: 1, fmt: (v: number) => `${Math.round(v)} ms`, label: "to verify a mint's solvency", color: C.green },
  { to: 16, fmt: (v: number) => `~${Math.round(v)} KB`, label: "proof, whether 1 or 64 ops", color: C.violetHi },
  { to: 49.6, fmt: (v: number) => `−${v.toFixed(1)}%`, label: "nullifier storage (Tachyon pruning)", color: C.orange },
  { to: 0, fmt: () => "0 sat", label: "fee to shield or unshield", color: C.sakura },
];
export const NUMBERS_STEP = 9;

/** 4 s. Scannable proof points. */
export const Numbers: React.FC = () => {
  const { vertical } = useLayout();
  const head = useSpring(0);
  return (
    <SceneShell>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", flexDirection: "column" }}>
        <div
          style={{
            fontSize: vertical ? 64 : 58,
            fontWeight: 900,
            letterSpacing: "-0.03em",
            marginBottom: 50,
            opacity: head,
            transform: `translateY(${(1 - head) * 20}px)`,
          }}
        >
          Measured, not promised.
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: vertical ? "1fr 1fr" : "repeat(4, 1fr)",
            gap: vertical ? 28 : 30,
            padding: "0 60px",
            width: vertical ? 1000 : 1800,
          }}
        >
          {STATS.map((s, i) => (
            <Stat key={i} {...s} delay={6 + i * NUMBERS_STEP} />
          ))}
        </div>
      </AbsoluteFill>
    </SceneShell>
  );
};

const Stat: React.FC<{ to: number; fmt: (v: number) => string; label: string; color: string; delay: number }> = ({
  to,
  fmt,
  label,
  color,
  delay,
}) => {
  const frame = useCurrentFrame();
  const s = useSpring(delay, { damping: 12, stiffness: 190 });
  const v = interpolate(frame, [delay, delay + 18], [0, to], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.out(Easing.cubic),
  });
  return (
    <div
      style={{
        background: `linear-gradient(160deg, ${rgba(color, 0.14)}, ${C.panel})`,
        border: `2px solid ${rgba(color, 0.5)}`,
        borderRadius: 26,
        padding: "40px 26px",
        textAlign: "center",
        transform: `translateY(${(1 - s) * 60}px)`,
        opacity: s,
        boxShadow: glow(color, 30, 0.15),
      }}
    >
      <div style={{ fontSize: 92, fontWeight: 900, color, letterSpacing: "-0.04em", lineHeight: 1 }}>{fmt(v)}</div>
      <div style={{ fontSize: 28, fontWeight: 600, color: C.dim, marginTop: 16, lineHeight: 1.25 }}>{label}</div>
    </div>
  );
};
