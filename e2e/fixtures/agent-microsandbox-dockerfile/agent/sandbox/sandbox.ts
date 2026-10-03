import { defineSandbox } from "orcel/sandbox";
import { MicrosandboxSandbox } from "orcel/sandbox/microsandbox";

export const environment = MicrosandboxSandbox.dockerfile({
  setup: { autoInstall: false },
});

export default defineSandbox(() => environment.open());
