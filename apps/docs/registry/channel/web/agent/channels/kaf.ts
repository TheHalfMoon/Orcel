import { kafChannel } from "kaf/channels/kaf";
import { localDev, placeholderAuth, vercelOidc } from "kaf/channels/auth";

export default kafChannel({
  auth: [
    // Lets the kaf TUI and your Vercel deployments reach the deployed agent.
    vercelOidc(),
    // Open on localhost for `kaf dev` and the REPL; ignored in production.
    localDev(),
    // This placeholder will not allow browser requests in production.
    // Replace it with your app's auth provider, like Auth.js or Clerk,
    // or use none() for a public demo.
    placeholderAuth(),
  ],
});
