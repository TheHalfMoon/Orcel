import { defineTool } from "orcel/tools";
import { never } from "orcel/tools/approval";
import { bash } from "orcel/tools/bash";

export default defineTool({ ...bash, approval: never() });
