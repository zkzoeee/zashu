import React from "react";
import { AbsoluteFill, useCurrentFrame, useVideoConfig } from "remotion";

const PETALS = Array.from({ length: 18 }, (_, i) => ({
  id: i,
  startX: ((i * 137) % 100) / 100,
  startY: ((i * 53) % 100) / 100,
  speedX: 0.25 + (i % 4) * 0.08,
  speedY: 0.35 + (i % 5) * 0.07,
  size: 12 + (i % 4) * 5,
  rotSpeed: (i % 2 === 0 ? 1 : -1) * (1.2 + (i % 3) * 0.5),
  tint: i % 3 === 0 ? "#c4b5fd" : "#f5a9cb",
}));

export const SakuraLayer: React.FC<{ opacity?: number }> = ({ opacity = 0.55 }) => {
  const frame = useCurrentFrame();
  const { width, height } = useVideoConfig();

  return (
    <AbsoluteFill style={{ pointerEvents: "none", overflow: "hidden", opacity }}>
      {PETALS.map((p) => {
        const x = ((p.startX * width + frame * p.speedX * 2.2) % (width + 100)) - 50;
        const y = ((p.startY * height + frame * p.speedY * 2.4) % (height + 100)) - 50;
        const rot = frame * p.rotSpeed;
        return (
          <svg
            key={p.id}
            width={p.size}
            height={p.size}
            viewBox="0 0 24 24"
            style={{
              position: "absolute",
              left: x,
              top: y,
              transform: `rotate(${rot}deg)`,
            }}
          >
            <path
              d="M12 2C7 5 5 11 12 22C19 11 17 5 12 2Z"
              fill={p.tint}
              opacity={0.75}
            />
          </svg>
        );
      })}
    </AbsoluteFill>
  );
};
