import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { C, MONO, glow, rgba, useLayout } from "../theme";
import { Caption, Chip, Flash, Kicker, SceneShell, Slash, useSpring } from "../components/ui";

const COINS = [
  { amt: 128, pow: "2⁷", at: 6 },
  { amt: 8, pow: "2³", at: 16 },
  { amt: 1, pow: "2⁰", at: 26 },
];
export const SHIELD_SLASH = 120;

/** 10 s. NUTZ-2: power-of-2 fingerprint → one shielded note. */
export const Shield: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const gap = vertical ? 270 : 300;
  const coinSize = vertical ? 210 : 220;
  const merge = interpolate(frame, [SHIELD_SLASH, SHIELD_SLASH + 10], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const scanY = interpolate(frame, [44, 74], [-160, 160], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const scanOn = frame >= 44 && frame < 80;
  const leak = useSpring(70, { damping: 12, stiffness: 200 });
  const card = useSpring(SHIELD_SLASH + 10, { damping: 13, stiffness: 150 });
  const centerY = vertical ? -40 : -20;

  return (
    <SceneShell>
      <Kicker spec="NUTZ-2" title="Shielded notes" />

      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center" }}>
        {/* Phase 1: three fingerprintable coins */}
        {merge < 1 && (
          <div style={{ position: "relative", transform: `translateY(${centerY}px)` }}>
            {/* what the mint learns */}
            <div
              style={{
                position: "absolute",
                left: "50%",
                top: -coinSize / 2 - 150,
                transform: `translateX(-50%) scale(${leak})`,
                opacity: leak * (1 - merge),
                whiteSpace: "nowrap",
                fontFamily: MONO,
                fontSize: vertical ? 34 : 38,
                fontWeight: 700,
                color: C.redHi,
                background: rgba(C.red, 0.14),
                border: `2px solid ${C.red}`,
                borderRadius: 14,
                padding: "12px 26px",
              }}
            >
              👁 mint sees: 128 + 8 + 1 = <b>137 sats</b>
            </div>

            {COINS.map((c, i) => (
              <Coin key={c.amt} {...c} i={i} gap={gap} size={coinSize} merge={merge} />
            ))}

            {/* red scan line = the mint looking */}
            {scanOn && (
              <div
                style={{
                  position: "absolute",
                  left: -gap - coinSize / 2 - 40,
                  width: gap * 2 + coinSize + 80,
                  top: scanY,
                  height: 4,
                  background: C.red,
                  boxShadow: `0 0 24px ${C.red}, 0 0 60px ${C.red}`,
                }}
              />
            )}
          </div>
        )}

        {/* Phase 2: one shielded note */}
        {frame >= SHIELD_SLASH + 8 && (
          <div
            style={{
              transform: `translateY(${centerY}px) scale(${interpolate(card, [0, 1], [0.4, 1])})`,
              opacity: card,
              display: "flex",
              flexDirection: vertical ? "column" : "row",
              borderRadius: 32,
              border: `4px solid ${C.violet}`,
              background: `linear-gradient(135deg, ${rgba(C.violet, 0.25)}, ${C.panel})`,
              boxShadow: glow(C.violet, 80, 0.5),
              overflow: "hidden",
            }}
          >
            <Half label="YOU SEE" w={vertical ? 760 : 560}>
              <div style={{ fontSize: 120, fontWeight: 900, color: C.orange, letterSpacing: "-0.04em", lineHeight: 1 }}>
                137<span style={{ fontSize: 50, color: C.text }}> sats</span>
              </div>
              <div style={{ fontSize: 28, color: C.dim, marginTop: 10, fontWeight: 600 }}>1 note · exact amount</div>
            </Half>
            <div style={{ width: vertical ? "100%" : 3, height: vertical ? 3 : "auto", background: rgba(C.violet, 0.5) }} />
            <Half label="MINT SEES" w={vertical ? 760 : 560}>
              <div style={{ fontFamily: MONO, fontSize: 40, color: C.violetHi, fontWeight: 700 }}>cm 0x7c1b…44e9</div>
              <div style={{ fontFamily: MONO, fontSize: 30, color: C.dim, marginTop: 14 }}>
                amount: <Redact w={150} />
              </div>
              <div style={{ fontFamily: MONO, fontSize: 30, color: C.green, marginTop: 8 }}>proof ✓ valid</div>
            </Half>
          </div>
        )}
      </AbsoluteFill>

      <Slash at={SHIELD_SLASH} />
      <Flash at={SHIELD_SLASH + 6} color={C.violet} max={0.25} />

      {frame >= 175 && (
        <div
          style={{
            position: "absolute",
            left: 0,
            right: 0,
            top: vertical ? 1290 : 790,
            display: "flex",
            justifyContent: "center",
            gap: 16,
            flexWrap: "wrap",
            padding: "0 60px",
          }}
        >
          <Chip delay={175}>Any amount</Chip>
          <Chip delay={181}>0-sat shield fee</Chip>
          <Chip delay={187}>Unshield to Cashu anytime</Chip>
        </div>
      )}

      <Caption at={4} until={SHIELD_SLASH - 2} text="Cashu tokens come in powers of 2 — and the split can fingerprint your amount." accent={["fingerprint"]} />
      <Caption at={SHIELD_SLASH + 4} text="Zashu shields them into one note. Any amount. Hidden from the mint." accent={["one", "note", "Hidden"]} />
    </SceneShell>
  );
};

const Half: React.FC<{ label: string; w: number; children: React.ReactNode }> = ({ label, w, children }) => (
  <div style={{ width: w, padding: "36px 44px", display: "flex", flexDirection: "column", alignItems: "center" }}>
    <div style={{ fontSize: 22, fontWeight: 800, letterSpacing: "0.18em", color: C.dim, marginBottom: 14 }}>{label}</div>
    {children}
  </div>
);

export const Redact: React.FC<{ w: number }> = ({ w }) => (
  <span
    style={{
      display: "inline-block",
      width: w,
      height: "0.8em",
      verticalAlign: "middle",
      borderRadius: 6,
      background: `repeating-linear-gradient(45deg, ${C.line}, ${C.line} 8px, ${C.panelHi} 8px, ${C.panelHi} 16px)`,
    }}
  />
);

const Coin: React.FC<{ amt: number; pow: string; at: number; i: number; gap: number; size: number; merge: number }> = ({
  amt,
  pow,
  at,
  i,
  gap,
  size,
  merge,
}) => {
  const s = useSpring(at, { damping: 10, stiffness: 190 });
  const powS = useSpring(56 + i * 5);
  const x = (i - 1) * gap * (1 - merge);
  return (
    <div
      style={{
        position: "absolute",
        left: x - size / 2,
        top: -size / 2,
        width: size,
        height: size,
        transform: `scale(${s * (1 - merge * 0.7)}) rotate(${(1 - s) * -90}deg)`,
        opacity: 1 - merge,
      }}
    >
      <div
        style={{
          width: "100%",
          height: "100%",
          borderRadius: "50%",
          background: `radial-gradient(circle at 35% 30%, #3a2a12, ${C.panel} 70%)`,
          border: `5px solid ${C.orange}`,
          boxShadow: glow(C.orange, 30, 0.35),
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <div style={{ fontSize: 80, fontWeight: 900, color: C.orange, lineHeight: 1 }}>{amt}</div>
        <div style={{ fontSize: 24, fontWeight: 600, color: C.dim, marginTop: 4 }}>sat</div>
      </div>
      <div
        style={{
          position: "absolute",
          left: 0,
          right: 0,
          top: size + 18,
          textAlign: "center",
          fontFamily: MONO,
          fontSize: 34,
          fontWeight: 700,
          color: C.redHi,
          opacity: powS,
        }}
      >
        {pow}
      </div>
    </div>
  );
};
