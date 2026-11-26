import { useVideoConfig } from "remotion";
import { loadFont } from "@remotion/google-fonts/ReggaeOne";

export const C = {
  // Matches the baked-in background of the mascot JPEGs so they blend seamlessly.
  bg: "#0c101b",
  panel: "#131a2a",
  panelHi: "#1a2338",
  line: "#26304a",
  text: "#eef2f7",
  dim: "#8b9bb4",
  violet: "#8b5cf6",
  violetHi: "#c4b5fd",
  orange: "#f7931a",
  green: "#3fb950",
  red: "#f85149",
  redHi: "#ff7b72",
  sakura: "#f5a9cb",
};

export const FONT =
  '"SF Pro Display", -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif';
export const MONO = '"SF Mono", ui-monospace, SFMono-Regular, Menlo, monospace';

/** Japanese display face for the wordmark and hanko stamps. */
export const JP = loadFont("normal", { weights: ["400"], subsets: ["latin"] }).fontFamily;

export const FPS = 30;

/** Layout helper: one code path for 16:9 and 9:16. */
export const useLayout = () => {
  const { width, height } = useVideoConfig();
  const vertical = height > width;
  return { width, height, vertical };
};

export const glow = (color: string, px = 40, a = 0.45) => {
  const hex = color.replace("#", "");
  const r = parseInt(hex.slice(0, 2), 16);
  const g = parseInt(hex.slice(2, 4), 16);
  const b = parseInt(hex.slice(4, 6), 16);
  return `0 0 ${px}px rgba(${r},${g},${b},${a})`;
};

export const rgba = (color: string, a: number) => {
  const hex = color.replace("#", "");
  const r = parseInt(hex.slice(0, 2), 16);
  const g = parseInt(hex.slice(2, 4), 16);
  const b = parseInt(hex.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${a})`;
};
