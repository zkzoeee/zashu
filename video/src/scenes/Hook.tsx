import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { C, rgba, useLayout } from "../theme";
import { SceneShell, useSpring } from "../components/ui";

const PROBLEMS = [
  { text: "Power-of-2 splits can fingerprint amounts", at: 62 },
  { text: "Locked payments show the mint who gets paid", at: 80 },
  { text: "No standard proof a mint is fully backed", at: 98 },
];

/** 0–5 s. Open on the problem, not the product. */
export const Hook: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const a = useSpring(0, { damping: 11, stiffness: 180 });
  const b = useSpring(14, { damping: 11, stiffness: 180 });
  const phase2 = frame >= 44;
  const lift = interpolate(frame, [44, 56], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const big = vertical ? 132 : 150;

  return (
    <SceneShell>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: 80 }}>
        <div
          style={{
            textAlign: "center",
            transform: `translateY(${lift * (vertical ? -260 : -190)}px) scale(${1 - lift * 0.55})`,
          }}
        >
          <div style={{ fontSize: big, fontWeight: 900, letterSpacing: "-0.045em", lineHeight: 1 }}>
            <span style={{ display: "inline-block", transform: `scale(${a})`, opacity: a }}>Cashu</span>{" "}
            <span style={{ display: "inline-block", transform: `scale(${a})`, opacity: a }}>is</span>{" "}
            <span
              style={{
                display: "inline-block",
                transform: `scale(${b}) skewX(-8deg)`,
                opacity: b,
                color: C.orange,
              }}
            >
              fast.
            </span>
          </div>
          {phase2 && (
            <div
              style={{
                fontSize: big * 0.62,
                fontWeight: 800,
                color: C.dim,
                marginTop: 18,
                opacity: lift,
                letterSpacing: "-0.03em",
                whiteSpace: "nowrap",
              }}
            >
              Where it could go further:
            </div>
          )}
        </div>

        {phase2 && (
          <div
            style={{
              position: "absolute",
              top: vertical ? 820 : 430,
              display: "flex",
              flexDirection: "column",
              gap: vertical ? 30 : 22,
              alignItems: "flex-start",
              padding: vertical ? "0 70px" : 0,
            }}
          >
            {PROBLEMS.map((p, i) => (
              <Problem key={i} {...p} />
            ))}
          </div>
        )}
      </AbsoluteFill>
    </SceneShell>
  );
};

const Problem: React.FC<{ text: string; at: number }> = ({ text, at }) => {
  const s = useSpring(at, { damping: 13, stiffness: 200 });
  const { vertical } = useLayout();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 24,
        opacity: s,
        transform: `translateX(${(1 - s) * -60}px)`,
      }}
    >
      <div
        style={{
          width: 56,
          height: 56,
          flexShrink: 0,
          borderRadius: 14,
          background: rgba(C.orange, 0.12),
          border: `2px solid ${rgba(C.orange, 0.7)}`,
          color: C.orange,
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          fontSize: 34,
          fontWeight: 900,
        }}
      >
        →
      </div>
      <div style={{ fontSize: vertical ? 46 : 52, fontWeight: 750, letterSpacing: "-0.02em", lineHeight: 1.1 }}>
        {text}
      </div>
    </div>
  );
};
