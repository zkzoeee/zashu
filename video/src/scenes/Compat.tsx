import React from "react";
import { AbsoluteFill, Easing, interpolate, interpolateColors, useCurrentFrame } from "remotion";
import { C, JP, glow, rgba, useLayout } from "../theme";
import { Caption, Kicker, SceneShell, useSpring } from "../components/ui";

export const COMPAT = {
  shieldStart: 46,
  shieldEnd: 76,
  unshieldStart: 108,
  unshieldEnd: 138,
  shared: 160,
};

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;
const ease = Easing.bezier(0.65, 0, 0.35, 1);

type P = { x: number; y: number };

/** 8 s. Zashu lives inside the same Cashu mint: shield/unshield, one Lightning, one solvency proof. */
export const Compat: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const frameIn = useSpring(0, { damping: 16, stiffness: 140 });

  // geometry in px from screen centre
  const G = vertical
    ? {
        box: { w: 960, h: 1090, cy: -20 },
        header: -500,
        cashu: { x: 0, y: -300, w: 860, h: 250 },
        zashu: { x: 0, y: 90, w: 860, h: 250 },
        shield: [{ x: -170, y: -165 }, { x: -170, y: -45 }] as [P, P],
        unshield: [{ x: 170, y: -45 }, { x: 170, y: -165 }] as [P, P],
        bars: [300, 380],
      }
    : {
        box: { w: 1600, h: 640, cy: -10 },
        header: -270,
        cashu: { x: -500, y: -60, w: 520, h: 300 },
        zashu: { x: 500, y: -60, w: 520, h: 300 },
        shield: [{ x: -215, y: -110 }, { x: 215, y: -110 }] as [P, P],
        unshield: [{ x: 215, y: 0 }, { x: -215, y: 0 }] as [P, P],
        bars: [160, 232],
      };

  const sh = interpolate(frame, [COMPAT.shieldStart, COMPAT.shieldEnd], [0, 1], { ...clamp, easing: ease });
  const un = interpolate(frame, [COMPAT.unshieldStart, COMPAT.unshieldEnd], [0, 1], { ...clamp, easing: ease });
  const lerp = (a: P, b: P, t: number) => ({ x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t });
  const tokenPos =
    frame < COMPAT.unshieldStart ? lerp(G.shield[0], G.shield[1], sh) : lerp(G.unshield[0], G.unshield[1], un);
  const tokenColor =
    frame < COMPAT.unshieldStart
      ? interpolateColors(sh, [0, 0.45, 0.55, 1], [C.orange, C.orange, C.violet, C.violet])
      : interpolateColors(un, [0, 0.45, 0.55, 1], [C.violet, C.violet, C.orange, C.orange]);
  const tokenOn =
    (frame >= COMPAT.shieldStart - 6 && frame <= COMPAT.shieldEnd + 14) ||
    (frame >= COMPAT.unshieldStart - 6 && frame <= COMPAT.unshieldEnd + 14);
  const tokenFade = Math.min(
    interpolate(frame, [COMPAT.shieldStart - 6, COMPAT.shieldStart], [0, 1], clamp) +
      interpolate(frame, [COMPAT.unshieldStart - 6, COMPAT.unshieldStart], [0, 1], clamp),
    1,
  ) *
    (frame < COMPAT.unshieldStart
      ? interpolate(frame, [COMPAT.shieldEnd + 6, COMPAT.shieldEnd + 14], [1, 0], clamp)
      : interpolate(frame, [COMPAT.unshieldEnd + 6, COMPAT.unshieldEnd + 14], [1, 0], clamp));

  return (
    <SceneShell>
      <Kicker spec="CASHU + ZASHU" title="Built on Cashu, not against it" color={C.orange} />

      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center" }}>
        <div style={{ position: "relative", width: 0, height: 0 }}>
          {/* the one mint */}
          <div
            style={{
              position: "absolute",
              left: -G.box.w / 2,
              top: G.box.cy - G.box.h / 2,
              width: G.box.w,
              height: G.box.h,
              borderRadius: 36,
              border: `3px solid ${C.line}`,
              background: `linear-gradient(180deg, ${rgba(C.panelHi, 0.7)}, ${rgba(C.panel, 0.35)})`,
              opacity: frameIn,
              transform: `scale(${interpolate(frameIn, [0, 1], [0.94, 1])})`,
            }}
          />
          <div
            style={{
              position: "absolute",
              left: 0,
              top: G.header,
              transform: "translate(-50%, -50%)",
              fontSize: 34,
              fontWeight: 800,
              color: C.dim,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              whiteSpace: "nowrap",
              opacity: frameIn,
            }}
          >
            🏯 one Cashu mint
          </div>

          <Lane
            at={G.cashu}
            delay={10}
            color={C.orange}
            name="Cashu"
            tag="BDHKE ecash"
            lines={["⚡ instant everyday payments", "✓ existing wallets unchanged"]}
            glowOn={interpolate(frame, [COMPAT.unshieldEnd - 4, COMPAT.unshieldEnd + 4, COMPAT.unshieldEnd + 20], [0, 1, 0], clamp)}
          />
          <Lane
            at={G.zashu}
            delay={20}
            color={C.violet}
            name="Zashu"
            tag="ZK shielded notes"
            lines={["🔒 private amounts & receivers", "🛡 hidden spending rules"]}
            glowOn={interpolate(frame, [COMPAT.shieldEnd - 4, COMPAT.shieldEnd + 4, COMPAT.shieldEnd + 20], [0, 1, 0], clamp)}
            jp
          />

          <Arrow from={G.shield[0]} to={G.shield[1]} label="shield" color={C.violetHi} delay={32} lit={sh} vertical={vertical} />
          <Arrow from={G.unshield[0]} to={G.unshield[1]} label="unshield" color={C.orange} delay={38} lit={un} vertical={vertical} />

          {/* fee chip between the arrows */}
          <FeeChip
            at={
              vertical
                ? { x: 0, y: (G.shield[0].y + G.shield[1].y) / 2 }
                : { x: 0, y: G.unshield[0].y + 52 }
            }
          />

          {tokenOn && (
            <div
              style={{
                position: "absolute",
                left: tokenPos.x,
                top: tokenPos.y,
                width: 70,
                height: 70,
                borderRadius: "50%",
                transform: "translate(-50%, -50%)",
                background: tokenColor,
                boxShadow: `0 0 30px ${tokenColor}`,
                border: "3px solid rgba(255,255,255,0.6)",
                opacity: tokenFade,
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                fontSize: 22,
                fontWeight: 900,
                color: "#fff",
                zIndex: 4,
              }}
            >
              137
            </div>
          )}

          <SharedBar y={G.bars[0]} w={G.box.w - 80} delay={COMPAT.shared} icon="⚡" text="One Lightning backend for both" color={C.orange} />
          <SharedBar y={G.bars[1]} w={G.box.w - 80} delay={COMPAT.shared + 8} icon="🛡" text="One solvency proof covers Cashu + Zashu" color={C.green} />
        </div>
      </AbsoluteFill>

      <Caption at={4} until={COMPAT.unshieldStart - 4} text="Zashu runs inside your existing Cashu mint." accent={["inside", "Cashu"]} />
      <Caption
        at={COMPAT.unshieldStart - 2}
        until={COMPAT.shared}
        text="Shield or unshield anytime, for 0 sats. Cashu wallets keep working."
        accent={["0", "sats", "keep", "working"]}
      />
      <Caption at={COMPAT.shared + 2} text="Same mint. Same Lightning. One audit for everything." accent={["One", "audit"]} />
    </SceneShell>
  );
};

const Lane: React.FC<{
  at: { x: number; y: number; w: number; h: number };
  delay: number;
  color: string;
  name: string;
  tag: string;
  lines: string[];
  glowOn: number;
  jp?: boolean;
}> = ({ at, delay, color, name, tag, lines, glowOn, jp }) => {
  const s = useSpring(delay, { damping: 13, stiffness: 170 });
  return (
    <div
      style={{
        position: "absolute",
        left: at.x - at.w / 2,
        top: at.y - at.h / 2,
        width: at.w,
        height: at.h,
        borderRadius: 26,
        border: `3px solid ${color}`,
        background: `linear-gradient(160deg, ${rgba(color, 0.16)}, ${C.panel})`,
        boxShadow: glow(color, 30 + glowOn * 60, 0.25 + glowOn * 0.5),
        padding: "26px 34px",
        transform: `scale(${s * (1 + glowOn * 0.03)})`,
        opacity: s,
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        zIndex: 2,
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
        <span
          style={{
            fontSize: 62,
            color: jp ? C.violetHi : color,
            fontFamily: jp ? JP : undefined,
            fontWeight: jp ? 400 : 900,
            letterSpacing: "-0.02em",
            lineHeight: 1,
          }}
        >
          {name}
        </span>
        <span
          style={{
            fontSize: 22,
            fontWeight: 700,
            color,
            border: `2px solid ${rgba(color, 0.55)}`,
            borderRadius: 999,
            padding: "4px 14px",
            whiteSpace: "nowrap",
          }}
        >
          {tag}
        </span>
      </div>
      {lines.map((l) => (
        <div key={l} style={{ fontSize: 30, fontWeight: 650, color: C.text, marginTop: 14, whiteSpace: "nowrap" }}>
          {l}
        </div>
      ))}
    </div>
  );
};

const Arrow: React.FC<{ from: P; to: P; label: string; color: string; delay: number; lit: number; vertical: boolean }> = ({
  from,
  to,
  label,
  color,
  delay,
  lit,
  vertical,
}) => {
  const s = useSpring(delay);
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const len = Math.hypot(dx, dy);
  const ang = (Math.atan2(dy, dx) * 180) / Math.PI;
  return (
    <div style={{ position: "absolute", left: from.x, top: from.y, opacity: s, zIndex: 3 }}>
      <div
        style={{
          position: "absolute",
          left: 0,
          top: -3,
          width: len * s,
          height: 6,
          borderRadius: 3,
          transformOrigin: "0 50%",
          transform: `rotate(${ang}deg)`,
          background: `linear-gradient(90deg, ${rgba(color, 0.35)}, ${color})`,
          boxShadow: lit > 0 && lit < 1 ? glow(color, 20, 0.9) : undefined,
        }}
      >
        <div
          style={{
            position: "absolute",
            right: -6,
            top: -9,
            width: 0,
            height: 0,
            borderTop: "12px solid transparent",
            borderBottom: "12px solid transparent",
            borderLeft: `20px solid ${color}`,
          }}
        />
      </div>
      <div
        style={{
          position: "absolute",
          left: dx / 2 + (vertical ? (dx === 0 ? (from.x < 0 ? -130 : 30) : 0) : 0),
          top: dy / 2 + (vertical ? -18 : -48),
          transform: vertical ? undefined : "translateX(-50%)",
          fontSize: 26,
          fontWeight: 800,
          color,
          whiteSpace: "nowrap",
          letterSpacing: "0.04em",
        }}
      >
        {label}
      </div>
    </div>
  );
};

const FeeChip: React.FC<{ at: P }> = ({ at }) => {
  const s = useSpring(COMPAT.shieldEnd + 6, { damping: 10, stiffness: 220 });
  return (
    <div
      style={{
        position: "absolute",
        left: at.x,
        top: at.y,
        transform: `translate(-50%, -50%) scale(${s})`,
        fontSize: 24,
        fontWeight: 800,
        color: C.green,
        background: rgba(C.green, 0.12),
        border: `2px solid ${rgba(C.green, 0.6)}`,
        borderRadius: 999,
        padding: "6px 16px",
        whiteSpace: "nowrap",
        zIndex: 5,
      }}
    >
      0 sat fee
    </div>
  );
};

const SharedBar: React.FC<{ y: number; w: number; delay: number; icon: string; text: string; color: string }> = ({
  y,
  w,
  delay,
  icon,
  text,
  color,
}) => {
  const s = useSpring(delay, { damping: 14, stiffness: 180 });
  return (
    <div
      style={{
        position: "absolute",
        left: -w / 2,
        top: y - 28,
        width: w,
        height: 56,
        borderRadius: 16,
        border: `2px solid ${rgba(color, 0.6)}`,
        background: rgba(color, 0.12),
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 14,
        fontSize: 30,
        fontWeight: 800,
        color: C.text,
        opacity: s,
        transform: `translateY(${(1 - s) * 30}px)`,
      }}
    >
      <span>{icon}</span>
      <span>{text}</span>
    </div>
  );
};
