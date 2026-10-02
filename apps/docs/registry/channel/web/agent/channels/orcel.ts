import { orcelChannel } from "orcel/channels/orcel";
import { localDev, placeholderAuth, vercelOidc } from "orcel/channels/auth";

export default orcelChannel({
  auth: [
    // Lets the orcel TUI and your Vercel deployments reach the deployed agent.
    vercelOidc(),
    // Open on localhost for `orcel dev` and the REPL; ignored in production.
    localDev(),
    // This placeholder will not allow browser requests in production.
    // Replace it with your app's auth provider, like Auth.js or Clerk,
    // or use none() for a public demo.
    placeholderAuth(),
  ],
});
