import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame, Easing } from "remotion";
import { C, MONO, glow, rgba, useLayout } from "../theme";
import { Caption, Kicker, Mascot, SceneShell, useSpring } from "../components/ui";
import { Redact } from "./Shield";

export const STEALTH = {
  sendStart: 36,
  atMint: 80,
  bobWakes: 196,
  deliverStart: 206,
  delivered: 238,
};

const ease = Easing.bezier(0.65, 0, 0.35, 1);

/** 10 s. NUTZ-3: pay a zsp1 stealth address while the receiver is offline. */
export const Stealth: React.FC = () => {
  const frame = useCurrentFrame();
  const { vertical } = useLayout();
  const D = vertical ? 520 : 640; // distance from the mint to each wallet
  const pos = (k: -1 | 0 | 1) => (vertical ? { x: 0, y: k * D - 10 } : { x: k * D, y: -30 });

  // Packet travel
  const leg1 = interpolate(frame, [STEALTH.sendStart, STEALTH.atMint], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: ease,
  });
  const leg2 = interpolate(frame, [STEALTH.deliverStart, STEALTH.delivered], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: ease,
  });
  const a = pos(-1);
  const m = pos(0);
  const b = pos(1);
  const park = { x: m.x, y: m.y + (vertical ? 215 : 230) };
  const px = frame < STEALTH.deliverStart ? a.x + (park.x - a.x) * leg1 : park.x + (b.x - park.x) * leg2;
  const py = frame < STEALTH.deliverStart ? a.y + (park.y - a.y) * leg1 : park.y + (b.y - park.y) * leg2;
  const packetVisible = frame >= STEALTH.sendStart && frame < STEALTH.delivered;
  const waiting = frame >= STEALTH.atMint && frame < STEALTH.deliverStart;
  const pulse = waiting ? 1 + Math.sin(frame / 4) * 0.06 : 1;
  const bobOn = interpolate(frame, [STEALTH.bobWakes, STEALTH.bobWakes + 10], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const got = useSpring(STEALTH.delivered, { damping: 9, stiffness: 180 });

  return (
    <SceneShell>
      <Kicker spec="NUTZ-3" title="Stealth payments, even offline" />

      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center" }}>
        <div style={{ position: "relative", width: 0, height: 0 }}>
          {/* wires */}
          <Wire from={a} to={park} lit={leg1} />
          <Wire from={park} to={b} lit={leg2} />

          <Node at={a} delay={2}>
            <Person file="zashi-var-zakura.jpg" name="Alice" sub="sends 37 sats" color={C.sakura} />
          </Node>

          <Node at={m} delay={8}>
            <MintPanel />
          </Node>

          <Node at={b} delay={14}>
            <div style={{ position: "relative" }}>
              <Person
                file="zashi-var-monk.jpg"
                name="Bob"
                sub={bobOn > 0.5 ? "back online" : "offline"}
                color={bobOn > 0.5 ? C.green : C.dim}
                dim={1 - bobOn}
              />
              {got > 0.01 && (
                <div
                  style={{
                    position: "absolute",
                    left: "50%",
                    top: vertical ? -40 : -70,
                    transform: `translateX(-50%) translateY(${(1 - got) * 30}px) scale(${got})`,
                    fontSize: 64,
                    fontWeight: 900,
                    color: C.green,
                    whiteSpace: "nowrap",
                    textShadow: glow(C.green, 30, 0.7),
                  }}
                >
                  +37 sats
                </div>
              )}
            </div>
          </Node>

          {waiting && (
            <div
              style={{
                position: "absolute",
                left: park.x,
                top: park.y + 48,
                transform: "translateX(-50%)",
                fontSize: 24,
                fontWeight: 700,
                color: C.green,
                whiteSpace: "nowrap",
                opacity: interpolate(frame, [STEALTH.atMint + 50, STEALTH.atMint + 60], [0, 1], {
                  extrapolateLeft: "clamp",
                  extrapolateRight: "clamp",
                }),
              }}
            >
              ✓ confirmed — can't be double-spent
            </div>
          )}

          {/* stealth packet */}
          {packetVisible && (
            <div
              style={{
                position: "absolute",
                left: px,
                top: py,
                transform: `translate(-50%, -50%) scale(${pulse})`,
                background: C.violet,
                color: "#fff",
                fontFamily: MONO,
                fontSize: 28,
                fontWeight: 800,
                padding: "12px 24px",
                borderRadius: 999,
                whiteSpace: "nowrap",
                boxShadow: `${glow(C.violet, 40, 0.9)}, 0 0 0 4px ${rgba("#ffffff", 0.15)}`,
                zIndex: 5,
              }}
            >
              🔒 zsp1q8x…f3k
            </div>
          )}
        </div>
      </AbsoluteFill>

      <Caption
        at={4}
        until={STEALTH.atMint + 40}
        text="Pay Bob's zsp1 stealth address — even while he's offline."
        accent={["zsp1", "offline"]}
      />
      <Caption
        at={STEALTH.atMint + 42}
        until={STEALTH.delivered - 4}
        text="The mint checks the math. It never sees who, or how much."
        accent={["never"]}
      />
      <Caption at={STEALTH.delivered} text="Bob comes online later. The payment is already his." accent={["already", "his"]} />
    </SceneShell>
  );
};

const Node: React.FC<{ at: { x: number; y: number }; delay: number; children: React.ReactNode }> = ({
  at,
  delay,
  children,
}) => {
  const s = useSpring(delay, { damping: 13, stiffness: 170 });
  return (
    <div
      style={{
        position: "absolute",
        left: at.x,
        top: at.y,
        transform: `translate(-50%, -50%) scale(${s})`,
        opacity: s,
      }}
    >
      {children}
    </div>
  );
};

const Person: React.FC<{ file: string; name: string; sub: string; color: string; dim?: number }> = ({
  file,
  name,
  sub,
  color,
  dim = 0,
}) => {
  const { vertical } = useLayout();
  return (
    <div
      style={{
        display: "flex",
        flexDirection: vertical ? "row" : "column",
        alignItems: "center",
        gap: vertical ? 10 : 0,
      }}
    >
      <Mascot
        file={file}
        size={vertical ? 260 : 300}
        style={{ filter: `grayscale(${dim}) brightness(${1 - dim * 0.45})` }}
      />
      <div style={{ textAlign: vertical ? "left" : "center", marginTop: vertical ? 0 : -16 }}>
        <div style={{ fontSize: 50, fontWeight: 900, letterSpacing: "-0.02em" }}>{name}</div>
        <div
          style={{
            display: "inline-block",
            marginTop: 6,
            fontSize: 26,
            fontWeight: 700,
            color,
            border: `2px solid ${rgba(color, 0.6)}`,
            background: rgba(color, 0.12),
            borderRadius: 999,
            padding: "4px 16px",
            whiteSpace: "nowrap",
          }}
        >
          {sub === "offline" ? "💤 offline" : sub}
        </div>
      </div>
    </div>
  );
};

const MintPanel: React.FC = () => {
  const frame = useCurrentFrame();
  const rows: [string, React.ReactNode, string][] = [
    ["nullifier", "0x9f3a…81c2", C.violetHi],
    ["commitment", "0x7c1b…44e9", C.violetHi],
    ["amount", <Redact key="a" w={170} />, C.dim],
    ["receiver", <Redact key="r" w={170} />, C.dim],
    ["proof", "✓ valid", C.green],
  ];
  return (
    <div
      style={{
        width: 470,
        background: C.panel,
        border: `3px solid ${C.violet}`,
        borderRadius: 26,
        padding: "26px 30px",
        boxShadow: glow(C.violet, 50, 0.35),
      }}
    >
      <div style={{ fontSize: 30, fontWeight: 900, marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        🏯 <span>Mint's view</span>
      </div>
      {rows.map(([k, v, color], i) => {
        const at = STEALTH.atMint + 4 + i * 8;
        const o = interpolate(frame, [at, at + 6], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
        return (
          <div
            key={k}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              fontFamily: MONO,
              fontSize: 26,
              padding: "7px 0",
              borderTop: i ? `1px solid ${C.line}` : undefined,
              opacity: o,
            }}
          >
            <span style={{ color: C.dim }}>{k}</span>
            <span style={{ color, fontWeight: 700 }}>{v}</span>
          </div>
        );
      })}
    </div>
  );
};

const Wire: React.FC<{ from: { x: number; y: number }; to: { x: number; y: number }; lit: number }> = ({
  from,
  to,
  lit,
}) => (
  <svg style={{ position: "absolute", left: 0, top: 0, overflow: "visible" }} width={1} height={1}>
    <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke={C.line} strokeWidth={4} strokeDasharray="14 12" />
    <line
      x1={from.x}
      y1={from.y}
      x2={from.x + (to.x - from.x) * lit}
      y2={from.y + (to.y - from.y) * lit}
      stroke={C.violet}
      strokeWidth={5}
      strokeLinecap="round"
      style={{ filter: `drop-shadow(0 0 8px ${C.violet})` }}
    />
  </svg>
);
