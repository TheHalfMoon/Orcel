// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// COPY_ADAPT from microsoft/Hybrid-Computer-Use at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1 (MIT), computer-use/internal/core.
// The per-file headers name each donor blob. The donor licence is
// apps/orcel-computer-host/third_party/hcu/LICENSE and the Orcel changes are
// listed in apps/orcel-computer-host/third_party/hcu/PATCHES.md.

// Package semantic is Orcel's semantic desktop layer for the private
// computer host: a compact accessibility tree with short refs, ref
// continuity across observations, live-target staleness checks, a semantic
// diff between observations, a window layout frame for GUI coordinates and a
// batch plan compiler.
//
// The package holds no authority. It never reads the desktop, sends input or
// decides policy: the host's native code reads the tree, orceld approves
// every action, and this package only narrows (it can refuse an action as
// stale, never admit one). Batched actions are compiled and validated here
// but are not dispatched by the host: the batch capability is refused until
// a grain amendment enables it (BatchDispatchEnabled).
package semantic
