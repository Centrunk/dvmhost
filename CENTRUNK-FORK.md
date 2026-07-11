# Centrunk fork of DVMProject/dvmhost

This is a **fork** of [DVMProject/dvmhost](https://github.com/DVMProject/dvmhost),
maintained by [Centrunk](https://github.com/Centrunk) for the myCTRS project. It
carries a **small, clearly-marked patch to SysView** so the myCTRS admin
"live FNE activity" screen can consume structured call events over SysView's
existing WebSocket (`HostWS`).

Everything else is upstream. The goal is to keep the delta tiny and rebasable —
all decode stays upstream; we only widen what SysView emits.

## Base

- **Upstream:** `DVMProject/dvmhost`
- **Base commit:** `435ff45b` (master HEAD at fork time — chosen over the
  `2026-03-06` tag because HEAD includes the broadcast-storm bugfix for radio-
  monitor packets, which directly affects a promiscuous monitor peer).
- **Branch:** `centrunk/sysview-netevent`

## The patch (one file)

`src/sysview/SysViewMain.cpp` — `threadNetworkPump()`.

Upstream already emits `net_event` WebSocket messages for trunking signaling
(P25 TSBK, DMR CSBK), and P25 voice **grants** already include `emerg`, `encry`,
`prio`, `chId`, `chNo`, `srcId/srcStr`, `dstId/dstStr`. What upstream does **not**
emit is the **voice call lifecycle** — it only writes those to the log via
`LogInfoEx()`. This fork adds a `g_netDataEvent(...)` emission at the 4 call
start/end sites so the lifecycle (and call duration) reaches the WebSocket.

Each added block is wrapped in banner comments so it is trivial to find on rebase:

```
// ===== BEGIN CENTRUNK FORK: ... (NOT upstream) =====
...
// ===== END CENTRUNK FORK =====
```

Patched sites (all mirror the existing `g_netDataEvent` emit idiom in the same
function):

| Mode | Event | Emits |
|------|-------|-------|
| P25  | `call_start` | `type, mode="p25", srcId, srcStr, dstId, dstStr, sysId, netId` |
| P25  | `call_end`   | above + `duration` |
| DMR  | `call_start` | `type, mode="dmr", slot, srcId, srcStr, dstId, dstStr` |
| DMR  | `call_end`   | above + `duration` |

`duration` mirrors the value in the adjacent upstream `Call End` log line
(`hrc::diff(...) / 1000`); its unit follows upstream and is calibrated during the
myCTRS spike (capture real values, confirm seconds vs. ms).

## Intentionally NOT patched

- **NXDN and Analog** call-start/end sites (also present in `threadNetworkPump()`)
  are left upstream-stock. CTRS is a P25 system (DMR patched as a bonus); NXDN/
  Analog never fire there. To add them later, replicate the same block at those
  sites — nothing else changes.
- `peerId` is **not** added to call events — it is not in scope at these sites.
  Per-site attribution for the live view comes from the `aff_list` message
  (which carries `peerId`); emergency/encryption for a call are joined from the
  P25 grant `net_event` (by `dstId`) on the consumer side.

## Build / run notes

- SysView **requires** the TUI to build: the `sysview` target is only produced
  under `ENABLE_TUI_SUPPORT=on` (default) `AND NOT DISABLE_TUI_APPS`; turning the
  flag off drops the target. Build **with** FinalCut, then run **daemonized**
  (SysView `HostWS` calls `fork()`/`setsid()` and detaches from the TTY).
- The WebSocket port comes from the SysView config (`fne-sysview.example.yml`);
  the myCTRS bridge connects to it over `localhost`.

## Rebasing onto a newer upstream

1. `git fetch upstream && git rebase <new-tag>`
2. Resolve conflicts only within the `CENTRUNK FORK` banner regions of
   `src/sysview/SysViewMain.cpp` (grep `CENTRUNK FORK`).
3. Update the **Base commit** above.

## Status

The patch is authored against upstream source but has **not yet been compiled**
in this environment (no CMake toolchain here) — first build happens in the
Centrunk build pipeline / spike box. Expect to iterate on any build errors there.
