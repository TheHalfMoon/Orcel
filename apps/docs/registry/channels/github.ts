import { connectGitHubCredentials } from "@vercel/connect/kaf";
import { githubChannel } from "kaf/channels/github";

export default githubChannel({
  credentials: connectGitHubCredentials("github/my-agent"),
});
