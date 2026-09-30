import { defineSandbox } from "kaf/sandbox";
import { DockerSandbox } from "kaf/sandbox/docker";
import { VercelSandbox } from "kaf/sandbox/vercel";

export const environment = process.env.VERCEL
  ? VercelSandbox.environment()
  : DockerSandbox.environment();

export default defineSandbox(() => environment.open({ networkPolicy: "deny-all" }));
