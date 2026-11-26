import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame, Easing } from "remotion";
import { C, JP, MONO, glow, rgba, useLayout } from "../theme";
import { Caption, Flash, Kicker, Mascot, SceneShell, useShake, useSpring } from "../components/ui";

export const BLOCK_HIT = 34;

/** 5 s. Replay the same note → bounced by the nullifier set. */
export const Blocked: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const shake = useShake(BLOCK_HIT, 14, 18);
  const inX = interpolate(frame, [6, BLOCK_HIT], [-1100, -330], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.in(Easing.quad),
  });
  const bounce = interpolate(frame, [BLOCK_HIT, BLOCK_HIT + 22], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.out(Easing.cubic),
  });
  const ghostX = frame < BLOCK_HIT ? inX : -330 - bounce * 520;
  const ghostY = frame < BLOCK_HIT ? 0 : bounce * 260;
  const ghostRot = bounce * -70;
  const stamp = useSpring(BLOCK_HIT + 2, { damping: 9, stiffness: 260 });
  const ring = interpolate(frame, [BLOCK_HIT, BLOCK_HIT + 18], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const scale = vertical ? 0.8 : 1;

  return (
    <SceneShell>
      <Kicker spec="SAFETY" title="Double-spend protection" color={C.green} />
      <Flash at={BLOCK_HIT} color={C.red} max={0.3} len={12} />

      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", transform: shake }}>
        <div style={{ position: "relative", width: 0, height: 0, transform: `translateY(${vertical ? -80 : -40}px) scale(${scale})` }}>
          {/* shockwave ring */}
          <div
            style={{
              position: "absolute",
              left: -260,
              top: -260,
              width: 520,
              height: 520,
              borderRadius: "50%",
              border: `6px solid ${C.violet}`,
              transform: `scale(${0.6 + ring * 0.9})`,
              opacity: frame >= BLOCK_HIT ? 1 - ring : 0,
            }}
          />
          {/* shield arc */}
          <div
            style={{
              position: "absolute",
              left: -230,
              top: -230,
              width: 460,
              height: 460,
              borderRadius: "50%",
              border: `5px solid ${rgba(C.violet, 0.7)}`,
              boxShadow: `${glow(C.violet, 50, 0.45)}, inset ${glow(C.violet, 40, 0.25)}`,
            }}
          />
          <div style={{ position: "absolute", left: -200, top: -200 }}>
            <Mascot file="zashi-var-cyber.jpg" size={400} />
          </div>

          {/* replayed note */}
          <div
            style={{
              position: "absolute",
              left: ghostX,
              top: ghostY,
              transform: `translate(-50%, -50%) rotate(${ghostRot}deg)`,
              opacity: frame < BLOCK_HIT ? 1 : 1 - bounce,
              fontFamily: MONO,
              fontSize: 30,
              fontWeight: 800,
              color: "#fff",
              background: rgba(C.red, 0.85),
              border: `3px solid ${C.redHi}`,
              borderRadius: 16,
              padding: "14px 24px",
              whiteSpace: "nowrap",
              boxShadow: glow(C.red, 40, 0.7),
            }}
          >
            ↻ same note again
          </div>
        </div>

        {/* stamp */}
        {frame >= BLOCK_HIT && (
          <div
            style={{
              position: "absolute",
              top: vertical ? 1240 : 760,
              left: 0,
              right: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              transform: `scale(${interpolate(stamp, [0, 1], [2.2, 1])}) rotate(-4deg)`,
              opacity: Math.min(1, stamp * 1.5),
            }}
          >
            <div
              style={{
                fontSize: 120,
                fontFamily: JP,
                fontWeight: 400,
                letterSpacing: "0.04em",
                color: C.redHi,
                border: `8px solid ${C.red}`,
                borderRadius: 20,
                padding: "0 40px",
                lineHeight: 1.1,
                background: rgba(C.red, 0.1),
                textShadow: glow(C.red, 30, 0.6),
              }}
            >
              BLOCKED
            </div>
          </div>
        )}
      </AbsoluteFill>

      <Caption
        at={BLOCK_HIT + 8}
        text="Spend a note twice? Its nullifier is already on record."
        accent={["nullifier"]}
      />
    </SceneShell>
  );
};
