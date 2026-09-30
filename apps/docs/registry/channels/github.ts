import { connectGitHubCredentials } from "@vercel/connect/eve";
import { githubChannel } from "kaf/channels/github";

export default githubChannel({
  credentials: connectGitHubCredentials("github/my-agent"),
});
