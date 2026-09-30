import { defineTool } from "kaf/tools";
import { never } from "kaf/tools/approval";
import { bash } from "kaf/tools/bash";

export default defineTool({ ...bash, approval: never() });
