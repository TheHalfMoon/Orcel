import { defineExtension } from "orcel/extension";

// No consumer config, so a bare defineExtension() — consumers mount it with a
// bare re-export.
export default defineExtension();
