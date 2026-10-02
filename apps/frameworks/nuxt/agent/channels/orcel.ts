import { localDev, none } from "orcel/channels/auth";
import { orcelChannel } from "orcel/channels/orcel";

// This example accepts anonymous traffic so the deployed demo is clickable in
// production. The deployment itself is gated by Vercel deployment protection.
// Swap `none()` for a real provider (Auth.js, Clerk, `vercelOidc()`, …) before
// exposing the agent publicly.
export default orcelChannel({
  auth: [localDev(), none()],
});
