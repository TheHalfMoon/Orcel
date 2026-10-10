---
"@orcel/orcel": patch
---

Avoid scheduling a durable sleep for an already-aborted tool call, and release the abort listener after a sleep finishes or is interrupted.
