import { defineSelfModificationSandbox } from "@orcel/orcel/self-modification/sandbox";
import selfModification from "../../extension.js";

export { defineSelfModificationSandbox } from "@orcel/orcel/self-modification/sandbox";

export default defineSelfModificationSandbox({ config: selfModification.config });
