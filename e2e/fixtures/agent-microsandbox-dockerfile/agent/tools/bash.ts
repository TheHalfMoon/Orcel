import { defineTool } from "@orcel/orcel/tools";
import { never } from "@orcel/orcel/tools/approval";
import { bash } from "@orcel/orcel/tools/bash";

export default defineTool({ ...bash, approval: never() });
