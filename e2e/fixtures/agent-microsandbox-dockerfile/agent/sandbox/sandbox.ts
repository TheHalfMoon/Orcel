import { defineSandbox } from "kaf/sandbox";
import { MicrosandboxSandbox } from "kaf/sandbox/microsandbox";

export const environment = MicrosandboxSandbox.dockerfile({
  setup: { autoInstall: false },
});

export default defineSandbox(() => environment.open());
