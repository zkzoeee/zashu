import React from "react";
import { Composition } from "remotion";
import { TOTAL_FRAMES, ZashuDemo } from "./ZashuDemo";
import { FPS } from "./theme";

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="ZashuDemo16x9"
        component={ZashuDemo}
        durationInFrames={TOTAL_FRAMES}
        fps={FPS}
        width={1920}
        height={1080}
      />
      <Composition
        id="ZashuDemo9x16"
        component={ZashuDemo}
        durationInFrames={TOTAL_FRAMES}
        fps={FPS}
        width={1080}
        height={1920}
      />
    </>
  );
};
