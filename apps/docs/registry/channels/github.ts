import { connectGitHubCredentials } from "@vercel/connect/eve";
import { githubChannel } from "@orcel/orcel/channels/github";

export default githubChannel({
  credentials: connectGitHubCredentials("github/my-agent"),
});
