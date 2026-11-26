import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { C, JP, MONO, glow, rgba, useLayout } from "../theme";
import { Mascot, SceneShell, useSpring } from "../components/ui";

// Main Zashi sits in the middle; landscape gets the full crew.
const CREW_WIDE = [
  "zashi-var-kitsune.jpg",
  "zashi-var-zakura.jpg",
  "zashi-var-cyber.jpg",
  "zashi-mascot.jpg",
  "zashi-var-monk.jpg",
  "zashi-var-tachyon.jpg",
  "zashi-var-satoshi.jpg",
];
const CREW_TALL = CREW_WIDE.slice(1, 6);
export const OUTRO_CREW_STEP = 5;
const CMD = "cargo run --release -p zashu-mint";
export const OUTRO_TYPE_AT = 40;

/** 5 s. The whole crew, the name, one command to try it. */
export const Outro: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const word = useSpring(18, { damping: 12, stiffness: 180 });
  const tag = useSpring(28);
  const box = useSpring(OUTRO_TYPE_AT - 6);
  const typed = Math.floor(interpolate(frame, [OUTRO_TYPE_AT, OUTRO_TYPE_AT + 30], [0, CMD.length], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  }));
  const url = useSpring(OUTRO_TYPE_AT + 36);
  const caret = Math.floor(frame / 8) % 2 === 0;
  const size = vertical ? 200 : 210;

  return (
    <SceneShell fadeOut={false}>
      <AbsoluteFill
        style={{
          justifyContent: "center",
          alignItems: "center",
          flexDirection: "column",
          background: `radial-gradient(circle at 50% 30%, ${rgba(C.violet, 0.22)}, transparent 55%)`,
        }}
      >
        <div style={{ display: "flex", alignItems: "flex-end", marginBottom: -10 }}>
          {(vertical ? CREW_TALL : CREW_WIDE).map((f, i, all) => {
            const mid = (all.length - 1) / 2;
            return (
              <CrewMember
                key={f}
                file={f}
                i={i}
                order={Math.abs(i - mid)}
                main={i === mid}
                size={i === mid ? size * 1.3 : size}
              />
            );
          })}
        </div>
        <div
          style={{
            fontSize: vertical ? 180 : 150,
            fontFamily: JP,
            fontWeight: 400,
            color: C.violetHi,
            letterSpacing: "-0.01em",
            lineHeight: 1,
            transform: `scale(${interpolate(word, [0, 1], [0.6, 1])})`,
            opacity: word,
            textShadow: glow(C.violet, 50, 0.5),
          }}
        >
          Zashu
        </div>
        <div
          style={{
            fontSize: vertical ? 50 : 46,
            fontWeight: 800,
            marginTop: 14,
            opacity: tag,
            letterSpacing: "-0.02em",
            textAlign: "center",
          }}
        >
          Cashu speed. <span style={{ color: C.violetHi }}>Shinobi privacy.</span>
        </div>

        <div
          style={{
            marginTop: 44,
            fontFamily: MONO,
            fontSize: vertical ? 34 : 36,
            color: C.orange,
            background: C.panel,
            border: `2px solid ${C.line}`,
            borderRadius: 16,
            padding: "18px 30px",
            opacity: box,
            transform: `translateY(${(1 - box) * 20}px)`,
            minWidth: vertical ? 760 : 800,
            whiteSpace: "pre",
          }}
        >
          <span style={{ color: C.dim }}>$ </span>
          {CMD.slice(0, typed)}
          <span style={{ opacity: caret ? 1 : 0, color: C.text }}>▌</span>
        </div>
        <div
          style={{
            marginTop: 20,
            fontSize: 32,
            fontWeight: 700,
            color: C.dim,
            opacity: url,
            textAlign: "center",
            padding: "0 60px",
            lineHeight: 1.4,
          }}
        >
          → open the Glass-Box Playground at <span style={{ color: C.text, fontFamily: MONO }}>localhost:8080/playground</span>
        </div>
      </AbsoluteFill>
    </SceneShell>
  );
};

const CrewMember: React.FC<{ file: string; i: number; order: number; main: boolean; size: number }> = ({
  file,
  i,
  order,
  main,
  size,
}) => {
  const frame = useCurrentFrame();
  // pop order: center first, then outwards in pairs
  const s = useSpring(order * OUTRO_CREW_STEP, { damping: 10, stiffness: 200 });
  const bob = Math.sin((frame + i * 9) / 11) * 6;
  return (
    <div
      style={{
        margin: `0 ${-size * 0.12}px`,
        transform: `translateY(${(1 - s) * 200 + bob}px) scale(${s})`,
        opacity: s,
        zIndex: main ? 2 : 1,
      }}
    >
      <Mascot file={file} size={size} />
    </div>
  );
};
