import React from "react";
import { AbsoluteFill, interpolate, interpolateColors, useCurrentFrame, Easing } from "remotion";
import { C, JP, MONO, glow, rgba, useLayout } from "../theme";
import { Caption, Flash, Kicker, Mascot, SceneShell, useShake, useSpring } from "../components/ui";

export const AUDIT = {
  fold: 62,
  folded: 80,
  panel: 140, // ~1.7 s hold on the folded 16 KB block
  verified: 178,
  stamp: 184,
  cheat: 241,
};

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

/** 9 s. NUTZ-1: fold everything into one tiny proof, check it against Bitcoin in 1 ms. */
export const Audit: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();

  return (
    <SceneShell>
      <Kicker spec="NUTZ-1" title="Proof of solvency" color={C.green} />
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center" }}>
        {/* sequential hand-off: the fold leaves completely before the panel enters */}
        {frame < AUDIT.panel && <FoldGrid />}
        {frame >= AUDIT.panel && <SolvencyPanel vertical={vertical} />}
      </AbsoluteFill>
      <Flash at={AUDIT.folded - 1} color={C.violet} max={0.12} len={8} />

      <Caption at={4} until={AUDIT.panel - 2} text="Every mint, swap and melt folds into one tiny proof." accent={["one", "tiny", "proof"]} />
      <Caption at={AUDIT.panel + 2} until={AUDIT.cheat - 2} text="Anyone checks it against on-chain Bitcoin — in 1 ms." accent={["Anyone", "1", "ms"]} />
      <Caption at={AUDIT.cheat + 6} text="Fractional reserve? The proof fails. Publicly." accent={["fails"]} />
    </SceneShell>
  );
};

const FoldGrid: React.FC = () => {
  const frame = useCurrentFrame();
  const fold = interpolate(frame, [AUDIT.fold, AUDIT.folded], [0, 1], { ...clamp, easing: Easing.in(Easing.cubic) });
  const block = useSpring(AUDIT.folded - 2, { damping: 12, stiffness: 200 });
  const out = interpolate(frame, [AUDIT.panel - 10, AUDIT.panel - 1], [1, 0], clamp);
  const outScale = interpolate(frame, [AUDIT.panel - 10, AUDIT.panel - 1], [1, 0.92], clamp);
  const labelOut = interpolate(frame, [AUDIT.fold - 6, AUDIT.fold + 4], [1, 0], clamp);
  const count = Math.min(64, Math.max(0, Math.floor((frame - 6) * 1.6)));
  const cell = 46;
  const { vertical } = useLayout();
  const chef = useSpring(10, { damping: 12, stiffness: 170 });
  return (
    <div
      style={{
        position: "relative",
        width: 0,
        height: 0,
        opacity: out,
        transform: `translateY(-30px) scale(${outScale})`,
      }}
    >
      <div
        style={{
          position: "absolute",
          left: vertical ? -150 : -700,
          top: vertical ? 250 : -170,
          textAlign: "center",
          opacity: chef,
          transform: `translateY(${(1 - chef) * 60}px)`,
        }}
      >
        <Mascot file="zashi-var-ragu.jpg" size={vertical ? 300 : 320} />
        <div style={{ fontSize: 30, fontWeight: 800, color: C.orange, marginTop: -20 }}>Ragu folding</div>
      </div>
      {Array.from({ length: 64 }, (_, i) => {
        const r = Math.floor(i / 8);
        const c = i % 8;
        const x0 = (c - 3.5) * cell;
        const y0 = (r - 3.5) * cell;
        const shown = i < count;
        // tiles stay solid, tint to violet as they converge, and vanish only once the block covers them
        const hue = interpolateColors(fold, [0, 0.7], [[C.orange, C.violet, C.green][i % 3], C.violet]);
        return (
          <div
            key={i}
            style={{
              position: "absolute",
              left: x0 * (1 - fold) - 18,
              top: y0 * (1 - fold) - 18,
              width: 36,
              height: 36,
              borderRadius: 8,
              background: rgba(C.panel, 0.4),
              border: `3px solid ${hue}`,
              opacity: shown && frame < AUDIT.folded ? 1 : 0,
              transform: `scale(${shown ? 1 - fold * 0.35 : 0.2})`,
              boxShadow: fold > 0.3 ? glow(C.violet, 16, fold * 0.6) : undefined,
            }}
          />
        );
      })}
      <div
        style={{
          position: "absolute",
          left: 0,
          top: -260,
          transform: "translateX(-50%)",
          fontFamily: MONO,
          fontSize: 34,
          fontWeight: 700,
          color: C.dim,
          whiteSpace: "nowrap",
          opacity: labelOut,
        }}
      >
        <span style={{ color: C.text }}>{String(count).padStart(2, "0")}</span> mint · swap · melt proofs
      </div>

      {frame >= AUDIT.folded - 2 && (
        <div
          style={{
            position: "absolute",
            left: 0,
            top: 0,
            transform: `translate(-50%, -50%) scale(${block})`,
            textAlign: "center",
          }}
        >
          <ProofBlock size={220} center />
          <div style={{ fontSize: 40, fontWeight: 800, marginTop: 24, whiteSpace: "nowrap" }}>
            1 folded proof <span style={{ color: C.dim, fontWeight: 600 }}>· any batch size</span>
          </div>
        </div>
      )}
    </div>
  );
};

const ProofBlock: React.FC<{ size: number; center?: boolean }> = ({ size, center }) => (
  <div
    style={{
      width: size,
      height: size,
      margin: center ? "0 auto" : 0,
      flexShrink: 0,
      borderRadius: size * 0.145,
      background: `linear-gradient(135deg, ${C.violet}, #5b3bc4)`,
      boxShadow: glow(C.violet, size * 0.32, 0.7),
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      fontSize: size * 0.29,
      fontWeight: 900,
      whiteSpace: "nowrap",
    }}
  >
    16 KB
  </div>
);

const SolvencyPanel: React.FC<{ vertical: boolean }> = ({ vertical }) => {
  const frame = useCurrentFrame();
  const enter = useSpring(AUDIT.panel, { damping: 14, stiffness: 160 });
  const badge = useSpring(AUDIT.panel + 2, { damping: 12, stiffness: 200 });
  const stamp = useSpring(AUDIT.stamp, { damping: 8, stiffness: 280 });
  const cheatStamp = useSpring(AUDIT.cheat + 10, { damping: 8, stiffness: 280 });
  const shake = useShake(AUDIT.stamp, 10, 12);
  const shake2 = useShake(AUDIT.cheat + 10, 12, 16);
  const msPop = useSpring(AUDIT.verified, { damping: 10, stiffness: 260 });
  const cheating = frame >= AUDIT.cheat;
  const W = vertical ? 900 : 1180;

  const reserves = interpolate(frame, [AUDIT.panel + 10, AUDIT.panel + 30], [0, 0.78], { ...clamp, easing: Easing.out(Easing.cubic) });
  const liabGrow = interpolate(frame, [AUDIT.panel + 16, AUDIT.panel + 36], [0, 0.62], { ...clamp, easing: Easing.out(Easing.cubic) });
  const liabCheat = interpolate(frame, [AUDIT.cheat, AUDIT.cheat + 12], [0, 0.34], { ...clamp, easing: Easing.out(Easing.back(2)) });
  const liab = liabGrow + liabCheat;
  // RGB-split glitch for a few frames when the cheat happens
  const g = frame >= AUDIT.cheat && frame < AUDIT.cheat + 14 ? ((frame * 7) % 5) - 2 : 0;
  const insolvent = cheating && frame >= AUDIT.cheat + 10;

  return (
    <div
      style={{
        width: W,
        transform: `translateY(${vertical ? -60 : -10}px) scale(${interpolate(enter, [0, 1], [0.85, 1])}) ${shake} ${shake2}`,
        opacity: enter,
        position: "relative",
        filter: g ? `drop-shadow(${g * 6}px 0 0 ${rgba(C.red, 0.8)}) drop-shadow(${-g * 6}px 0 0 rgba(0,200,255,0.6))` : undefined,
      }}
    >
      {/* carries the folded proof over from the previous beat */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 18,
          marginBottom: 36,
          opacity: badge,
          transform: `translateX(${(1 - badge) * -40}px)`,
        }}
      >
        <ProofBlock size={64} />
        <div style={{ fontSize: 32, fontWeight: 800, color: C.violetHi }}>
          folded proof <span style={{ color: C.dim, fontWeight: 600 }}>checked against</span>
        </div>
      </div>

      <Bar label="Bitcoin reserves" sub="on-chain Taproot UTXOs" value={reserves} color={C.orange} />
      <div style={{ height: 34 }} />
      <Bar
        label="Ecash liabilities"
        sub="every token the mint issued"
        value={liab}
        color={cheating ? C.red : C.violet}
        over={liab > reserves + 0.001}
      />

      <div
        style={{
          marginTop: 40,
          display: "flex",
          alignItems: "center",
          justifyContent: vertical ? "center" : "space-between",
          flexDirection: vertical ? "column" : "row",
          gap: vertical ? 40 : 0,
        }}
      >
        <div style={{ fontFamily: MONO, fontSize: 36, color: C.dim }}>
          {frame < AUDIT.verified ? (
            <span>verifying{".".repeat(1 + (Math.floor(frame / 5) % 3))}</span>
          ) : (
            <>
              verified in{" "}
              <span
                style={{
                  display: "inline-block",
                  color: C.text,
                  fontWeight: 900,
                  fontSize: 72,
                  transform: `scale(${interpolate(msPop, [0, 1], [1.8, 1])})`,
                }}
              >
                1 ms
              </span>
            </>
          )}
        </div>

        <div style={{ position: "relative", width: 470, height: 150 }}>
          {frame >= AUDIT.stamp && (
            <Hanko
              text={insolvent ? "INSOLVENT" : "SOLVENT"}
              color={insolvent ? C.red : C.green}
              s={insolvent ? cheatStamp : stamp}
            />
          )}
        </div>
      </div>
      {cheating && <Flash at={AUDIT.cheat} color={C.red} max={0.15} />}
    </div>
  );
};

const Bar: React.FC<{ label: string; sub: string; value: number; color: string; over?: boolean }> = ({
  label,
  sub,
  value,
  color,
  over,
}) => (
  <div>
    <div style={{ display: "flex", alignItems: "baseline", gap: 16, marginBottom: 12 }}>
      <span style={{ fontSize: 40, fontWeight: 850, color }}>{label}</span>
      <span style={{ fontSize: 26, color: C.dim, fontWeight: 600 }}>{sub}</span>
    </div>
    <div style={{ position: "relative", height: 56, borderRadius: 14, background: C.panel, border: `2px solid ${C.line}` }}>
      <div
        style={{
          position: "absolute",
          left: 0,
          top: 0,
          bottom: 0,
          width: `${value * 100}%`,
          borderRadius: 12,
          background: `linear-gradient(90deg, ${rgba(color, 0.55)}, ${color})`,
          boxShadow: over ? glow(color, 40, 0.8) : glow(color, 20, 0.35),
        }}
      />
    </div>
  </div>
);

const Hanko: React.FC<{ text: string; color: string; s: number }> = ({ text, color, s }) => (
  <div
    style={{
      position: "absolute",
      right: 0,
      top: 0,
      left: 0,
      bottom: 0,
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      transform: `scale(${interpolate(s, [0, 1], [2.6, 1])}) rotate(-6deg)`,
      opacity: Math.min(1, s * 1.6),
    }}
  >
    <div
      style={{
        fontSize: 86,
        fontFamily: JP,
        fontWeight: 400,
        letterSpacing: "0.05em",
        color,
        border: `8px double ${color}`,
        borderRadius: 18,
        padding: "0 30px",
        lineHeight: 1.25,
        background: rgba(color, 0.1),
        textShadow: glow(color, 24, 0.6),
      }}
    >
      {text}
    </div>
  </div>
);
