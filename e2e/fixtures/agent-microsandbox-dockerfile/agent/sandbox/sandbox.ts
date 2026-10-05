import { defineSandbox } from "@orcel/orcel/sandbox";
import { MicrosandboxSandbox } from "@orcel/orcel/sandbox/microsandbox";

export const environment = MicrosandboxSandbox.dockerfile({
  setup: { autoInstall: false },
});

export default defineSandbox(() => environment.open());
