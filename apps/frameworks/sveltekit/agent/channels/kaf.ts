import { localDev, none } from "kaf/channels/auth";
import { kafChannel } from "kaf/channels/kaf";

// This example accepts anonymous traffic so the deployed demo is clickable in
// production. The deployment itself is gated by Vercel deployment protection.
// Swap `none()` for a real provider (Auth.js, Clerk, `vercelOidc()`, ...) before
// exposing the agent publicly.
export default kafChannel({
  auth: [localDev(), none()],
});
