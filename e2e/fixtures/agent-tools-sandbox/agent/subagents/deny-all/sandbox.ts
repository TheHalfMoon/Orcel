import { defineSandbox } from "@orcel/orcel/sandbox";
import { DockerSandbox } from "@orcel/orcel/sandbox/docker";
import { VercelSandbox } from "@orcel/orcel/sandbox/vercel";

export const environment = process.env.VERCEL
  ? VercelSandbox.environment()
  : DockerSandbox.environment();

export default defineSandbox(() => environment.open({ networkPolicy: "deny-all" }));
