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
special WUIDs. `roamingSysIds` must be a YAML list; an absent key, an empty value, or `[]` means an empty
list (a single scalar such as `roamingSysIds: 2A5` is rejected rather than read as "any System
ID", and the error is logged only when `allowRoaming` is enabled), and every entry must be a clean hexadecimal
12-bit value (an optional `0x` prefix is accepted; signs, whitespace, and trailing characters
are not) other than `$000` and the site System ID.
Any error is logged and roaming stays disabled. A warning is logged if RID ACL entries fall
inside the pool; pool WUIDs must never be assigned to home radios, and a home SU whose Unit ID
lies inside the pool is refused.

## Admission order

1. Different WACN ID: REG_DENY (extended format).
2. Home SU: existing behavior (RID ACL, `requireLLAForReg`, automatic inhibit). A home Unit ID
   inside the roaming pool is answered with REG_REFUSED.
3. Roaming SU:
   - `allowRoaming` false: REG_DENY.
   - System ID `$000`: REG_DENY.
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
- Unit-addressed requests from Home SUs to a pool WUID (unit-to-unit voice and answer, call
  alert, status and message updates, radio monitor) are denied with `DENY_SYS_UNSUPPORTED_SVC`
  and are not mirrored to the network. Acknowledgement, status query, and extended function
  responses addressed to a pool WUID are consumed locally and not forwarded. Unit-to-unit voice
  and PDUs (including the source of an extended-address PDU) that carry a pool WUID are not
  written to the network, and periodic registration and affiliation announcements omit pool
  WUIDs.
- U_DE_REG_REQ carries the SU's SUID, not its WUID (TIA-102.AABC-D 6.1.17). A request whose SUID
  belongs to a registered roaming SU releases that SU's WUID; it is acknowledged with the SU's own
  WACN ID and System ID and is not subject to the RID ACL or automatic inhibit. ACK_RSP_FNE to a
  roaming or foreign U_REG_REQ likewise names the requesting SUID and does not refresh any
  registration timer. A U_DE_REG_REQ carrying the site's WACN ID and System ID with a Unit ID inside
  the roaming pool is not a roaming SU's SUID; it is logged and ignored and never releases a WUID.

WUIDs are released on de-registration and WUID validity expiry (`wuidValidity`). The pool is held
in memory; a restart clears it and roaming SUs re-register. When unit registration timeouts are
disabled (`disableUnitRegTimeout`, or `wuidValidity` 255), WUIDs of roaming SUs that leave without
de-registering are never released and the pool can be exhausted; a warning is logged at startup.

A forced de-registration (for example over REST) that runs between WUID allocation and unit
registration of the same roaming SU can leave the SU registered without a WUID mapping. The window
is small, and the next request from the SU is answered with a Unit Registration Command.

## Behavior changes regardless of `allowRoaming`

These follow the standard but are visible on air even with roaming disabled:

- An SU from a different WACN whose System ID matches the site was previously accepted; it is now
  denied with the extended-format response.
- A REG_DENY for a different System ID now carries the SU's own System ID and Source Address
  `$000000` (previously the site System ID and the Unit ID) and no longer triggers automatic
  inhibit.
- LOC_REG_RSP now encodes the Site ID (and the RFSS ID) in their correct octets.
- A U_DE_REG_REQ whose WACN ID or System ID differs from the site no longer de-registers the Home
  SU that has the same Unit ID. It is applied only to a registered roaming SU with that SUID, and
  is otherwise logged and ignored.

## Subscriber programming

An SU must accept the site's WACN ID and System ID before it transmits on the control channel
(TIA-102.AABD-B 5.4.5). For Motorola APX radios this typically requires an intra-WACN roaming
coverage type, the site control channels in the radio's control channel list, and a NAC/System ID
combination that satisfies the radio's NAC validation setting.
