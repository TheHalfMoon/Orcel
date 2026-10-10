---
"@orcel/orcel": patch
---

Keep session lookup and delivery fail-closed while a deployment handoff marker is active, preventing a temporarily unclaimed inbox from being mistaken for an absent session.
