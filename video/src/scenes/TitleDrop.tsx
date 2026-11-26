import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { C, JP, glow, rgba, useLayout } from "../theme";
import { Chip, Flash, Mascot, SceneShell, Slash, useSpring } from "../components/ui";

/** 3 s. Katana slash → Zashi lands → name + one-line promise. */
export const TitleDrop: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const drop = useSpring(6, { damping: 10, stiffness: 170 });
  const word = useSpring(14, { damping: 13, stiffness: 190 });
  const tag = useSpring(24);
  const halo = interpolate(frame, [6, 30], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  return (
    <SceneShell>
      <AbsoluteFill
        style={{
          background: `radial-gradient(circle at 50% ${vertical ? 40 : 42}%, ${rgba(C.violet, 0.35 * halo)}, transparent 45%)`,
        }}
      />
      <Slash at={0} />
      <Flash at={6} max={0.18} />
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", flexDirection: "column" }}>
        <div style={{ transform: `translateY(${(1 - drop) * -500}px)` }}>
          <Mascot file="zashi-mascot.jpg" size={vertical ? 520 : 400} />
        </div>
        <div
          style={{
            fontSize: vertical ? 190 : 170,
            fontFamily: JP,
            fontWeight: 400,
            color: C.violetHi,
            letterSpacing: "-0.01em",
            lineHeight: 0.95,
            marginTop: -20,
            transform: `scale(${interpolate(word, [0, 1], [1.4, 1])})`,
            opacity: word,
            textShadow: glow(C.violet, 50, 0.5),
          }}
        >
          Zashu
        </div>
        <div
          style={{
            fontSize: vertical ? 44 : 42,
            fontWeight: 700,
            color: C.violetHi,
            marginTop: 22,
            opacity: tag,
            transform: `translateY(${(1 - tag) * 20}px)`,
            textAlign: "center",
            padding: "0 60px",
          }}
        >
          Zero-knowledge privacy &amp; solvency proofs for Cashu
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 30, flexWrap: "wrap", justifyContent: "center" }}>
          <Chip delay={36} color={C.orange}>Same mint</Chip>
          <Chip delay={41} color={C.orange}>Same Lightning</Chip>
          <Chip delay={46} color={C.orange}>Drop-in</Chip>
        </div>
      </AbsoluteFill>
    </SceneShell>
  );
};
