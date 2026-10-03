import { ImageResponse } from "next/og";
import { OrcelImageMark } from "./_components/orcel-image-mark";

export const size = {
  width: 180,
  height: 180,
};

export const contentType = "image/png";

export default function AppleIcon() {
  return new ImageResponse(
    <div
      style={{
        alignItems: "center",
        background: "#050505",
        display: "flex",
        height: "100%",
        justifyContent: "center",
        width: "100%",
      }}
    >
      <OrcelImageMark size={122} />
    </div>,
    size,
  );
}
