---
"kaf": patch
---

Add an optional `fallback` model to `auto` model routing. When the evaluation model fails, kaf now uses the configured fallback for the rest of the turn while preserving cancellation behavior.
