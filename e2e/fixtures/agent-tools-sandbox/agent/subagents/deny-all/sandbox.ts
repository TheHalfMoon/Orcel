import { defineSandbox } from "orcel/sandbox";
import { DockerSandbox } from "orcel/sandbox/docker";
import { VercelSandbox } from "orcel/sandbox/vercel";

export const environment = process.env.VERCEL
  ? VercelSandbox.environment()
  : DockerSandbox.environment();

export default defineSandbox(() => environment.open({ networkPolicy: "deny-all" }));
