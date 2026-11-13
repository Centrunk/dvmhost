# P25 Roaming Registration

This note describes how `dvmhost` registers P25 subscriber units (SUs) homed to another
System ID within the same WACN.

## Identity model

A P25 SU is identified by its SUID: WACN ID, System ID, and 24-bit Unit ID. A roaming SU
registers with its Home System identity (TIA-102.AABD-B 6.4.1). The registering site assigns
a locally significant Working Unit ID (WUID):

- A Home SU (same WACN ID and System ID as the site) uses its Unit ID as its WUID.
- A roaming SU (same WACN ID, different System ID) receives a WUID from the configured
  roaming pool (TIA-102.AABD-B 6.2).
- An SU from a different WACN is denied with the extended-format Unit Registration Response
  (TIA-102.AABC-D 6.2.21.2).

## Configuration (`protocols.p25`)

| Key | Default | Meaning |
| --- | --- | --- |
| `allowRoaming` | `false` | Allow SUs homed to other System IDs in this WACN to register. |
| `roamingSysIds` | `[]` | Home System IDs (hex strings) permitted to roam here; empty permits any System ID in this WACN. |
| `roamingWuidStart` | `0` | First WUID of the roaming pool (decimal, inclusive). |
| `roamingWuidEnd` | `0` | Last WUID of the roaming pool (decimal, inclusive). |

The pool must satisfy `0 < roamingWuidStart <= roamingWuidEnd` and lie below the reserved
special WUIDs. Every `roamingSysIds` entry must be a 12-bit value other than the site System ID.
Any error is logged and roaming stays disabled. A warning is logged if RID ACL entries fall
inside the pool; pool WUIDs must never be assigned to home radios, and a home SU whose Unit ID
lies inside the pool is refused.

## Admission order

1. Different WACN ID: REG_DENY (extended format).
2. Home SU: existing behavior (RID ACL, `requireLLAForReg`, automatic inhibit). A home Unit ID
   inside the roaming pool is answered with REG_REFUSED.
3. Roaming SU:
   - `allowRoaming` false: REG_DENY.
   - System ID not in a non-empty `roamingSysIds`: REG_DENY.
   - Pool exhausted: REG_DENY.
   - Otherwise REG_ACCEPT with the SU's Home System ID, Unit ID, and assigned WUID.

Roaming SUs are not checked against the RID ACL, are never automatically inhibited, and are not
LLA-authenticated even when `requireLLAForReg` is enabled. Admission relies only on the WACN ID
and `roamingSysIds`.

Roaming admission failures deliberately use REG_DENY rather than REG_REFUSED. An SU receiving
REG_REFUSED may enter the "Invalid ID" state and wait for user input (TIA-102.AABD-B 6.4.1.2),
which could strand a public-safety radio on a system that will not serve it. REG_DENY makes the
SU mark the site as denied and resume control channel hunting, so it finds its home system
without user action.

## Current limitations

Roaming SUs are served locally only until roaming identity translation is implemented:

- Group affiliation, location registration, and de-registration are processed locally and are
  not announced to the network. These requests also restart the WUID validity timer.
- Voice, data, unit-to-unit, telephone interconnect, status, message, call alert, and extended
  function requests are denied with `DENY_SYS_UNSUPPORTED_SVC`.
- Emergency alarms are acknowledged and logged (warning and activity log with SUID, WUID, and
  site) but are not forwarded to the network.
- Acknowledgement, status query, group affiliation query, authentication, and radio monitor
  responses from a roaming SU are ignored (logged only in verbose mode).
- A request from an unassigned pool WUID (including the responses above) is answered with a
  Unit Registration Command.

WUIDs are released on de-registration and WUID validity expiry (`wuidValidity`). The pool is held
in memory; a restart clears it and roaming SUs re-register.

## Subscriber programming

An SU must accept the site's WACN ID and System ID before it transmits on the control channel
(TIA-102.AABD-B 5.4.5). For Motorola APX radios this typically requires an intra-WACN roaming
coverage type, the site control channels in the radio's control channel list, and a NAC/System ID
combination that satisfies the radio's NAC validation setting.
