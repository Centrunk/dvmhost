# P25 Roaming Registration

This note describes how `dvmhost` registers P25 subscriber units (SUs) homed to another
System ID within the same WACN, and how linked DVM FNEs authorize, track and deregister those
SUs between their home and serving systems (TIA-102.BACA-B Home and Serving RFSS roles carried
over DVM FNE messages).

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
| `roamingAllowUnverified` | `false` | When the home system cannot be reached (timeout, no route, an FNE link without P25 roaming, a lost FNE link, or no network), admit the SU with REG_FAIL and a local WUID instead of REG_DENY. |
| `roamingHomeTimeout` | `5000` | Milliseconds to wait for the home system's Serving Registration response (an engineering choice; the standards define no SU wait time). `0` is replaced by the default with a warning. |

The pool must satisfy `0 < roamingWuidStart <= roamingWuidEnd` and lie below the reserved
special WUIDs. `roamingSysIds` must be a YAML list; an absent key, an empty value, or `[]` means an empty
list (a single scalar such as `roamingSysIds: 2A5` is rejected rather than read as "any System
ID", and the error is logged only when `allowRoaming` is enabled), and every entry must be a clean hexadecimal
12-bit value (an optional `0x` prefix is accepted; signs, whitespace, and trailing characters
are not) other than `$000` and the site System ID.
Any error is logged and roaming stays disabled. A warning is logged if RID ACL entries fall
inside the pool; pool WUIDs must never be assigned to home radios, and a home SU whose Unit ID
lies inside the pool is refused.

## FNE system identity (`system`)

| Key | Default | Meaning |
| --- | --- | --- |
| `p25NetId` | unset (example: `0`) | This system's WACN ID (hexadecimal, 1 - FFFFF). |
| `p25SysId` | unset (example: `0`) | This system's System ID (hexadecimal, 1 - FFF). |
| `p25RoamingExpires` | `18000` | Seconds a home registration lasts; values of 14400 or less disable roaming at startup (an error is logged and the FNE keeps running without roaming). |

Exactly one FNE per system (WACN ID + System ID) may set `p25NetId` and `p25SysId`: that FNE is the
system's home, because each SU has exactly one Home RFSS found from its WACN ID and System ID
(TIA-102.BACA-B 2.1.3.1.1). Downstream FNEs of the same system must leave both keys unset. A downstream
FNE that offers this FNE's own identity at login, or an upstream master that answers with it, is logged
as a warning naming the peer and the link is treated as not roaming capable.

P25 roaming between DVM systems is negotiated only when both identity keys are set to non-zero
values. Both absent, or both `0` (as in `fne-config.example.yml`), means the FNE has no P25
identity and behaves as it did before roaming; setting only one of the two disables roaming and
logs an error. A WACN ID in BEE00 - BEEFF stops the FNE from starting whatever `p25SysId` holds;
this protection must never be disabled (see the WACN restrictions in `AGENTS.md`). The same range is
refused from peers: a host or downstream FNE that offers a WACN ID in BEE00 - BEEFF at login is rejected
(RPTC NAK).

While the FNE has an identity, a host that offers a `rfssConfig` WACN ID or System ID different from
it is rejected at login (RPTC NAK, logged as an identity mismatch). Only a host with P25 enabled
and `protocols.p25.allowRoaming: true` offers its identity (`p25Roaming` in the RPTC configuration).
A host that offers none (P25 disabled or `allowRoaming` off, as for conventional, DVRS and voice
channel hosts) is never identity-checked and can share the FNE unchanged. A downstream neighbor FNE is exempt from the mismatch check because it
has an identity of its own; the neighbor decision uses the same peer class precedence (`peerClass`
over the legacy `externalPeer`) as the peer class the FNE stores for the connection. A downstream FNE
offers its own `p25NetId` and `p25SysId`, and an FNE with an identity offers it to its upstream
master. The master answers in the RPTC ACK. A link carries roaming messages only when both ends
advertised roaming; a link that did not negotiate it behaves exactly as before and stays silent in
the roaming log.

## Home authorization (Serving Registration)

1. The site runs the local checks above. Failures answer REG_DENY.
2. The site sends ACK_RSP_FNE (AIV=1/EX=1, addressed to the SUID) so the SU is covered while the home
   is asked. With `ackRequests` enabled it is sent with the request as for any SU; with `ackRequests`
   disabled a roamer that passes the local checks still receives it. The site then asks the home system
   through its FNE (`ROAM_SERVING_REG`, presence Confirmed). Retries while waiting get ACK_RSP_FNE only.
3. FNEs route the request by (WACN, System ID); an unknown system goes to the roaming-capable upstream
   master, and a request is never forwarded back out the link it arrived on. The home FNE checks its RID
   ACL (unit present and enabled), records where the SU is served, and answers with `expires`, access
   and the radio inhibit flag. The DVM home FNE always answers access full and not inhibited; the host
   honors the other access and inhibit values if a home returns them. The home then deregisters the
   previous serving system (Roamed) and any registration on its own sites.
4. The site answers on air. Every message driven by the home's outcome uses the standard MFID.
   - Success with access full or emergency only: REG_ACCEPT with a WUID. Inhibited radios are then
     inhibited by WUID. Any other access value is treated as no access, and a response with an
     undefined access or flags value is rejected by the codec.
   - Success with access none, and every home failure code: REG_DENY.
   - FAILED: REG_DENY, or with `roamingAllowUnverified` REG_FAIL with a local WUID. A roamer the host
     already holds is not denied: it is re-accepted with its existing WUID and stored profile (the
     radio inhibit is applied again).
5. The site refreshes the registration at 80 % of `expires` (presence Not Confirmed), or with presence
   Confirmed when the SU registers again. A refresh the home rejects releases the roamer silently; a
   refresh that fails keeps the roamer and retries after RetryTime. A Not Confirmed refresh for an SU the
   home records at a different serving RFSS is answered `MME_MUST_CONFIRM_SU_PRESENCE` and the home keeps
   its record, so a site that missed a Home Deregistration releases the roamer instead of taking it back.

An unreachable home produces no message on the wire: FAILED has no encoding. A host whose own FNE link
did not negotiate roaming, or has no network, completes as FAILED immediately. Otherwise, when the
FNE has no route toward the home (or the home never answers), the FNE sends nothing to a host and the
host's `roamingHomeTimeout` produces FAILED; a request relayed from a downstream FNE with no onward
route is answered `MME_SU_UNKNOWN`. After FAILED the site does not ask the home again for that SU for
10 seconds (RetryTime); an SU retry inside that window gets the FAILED policy at once.

When an FNE link is lost, the host completes its pending Serving Registrations as FAILED and keeps
its registered roamers until their WUIDs expire. On the first clock pass that sees the link capable
again, after any observed link loss, the host resynchronizes every roamer it holds with the home
(presence Not Confirmed).

A roamer leaving (U_DE_REG_REQ, WUID expiry, or no answer to a Forced query) is reported to the home
(`ROAM_SERVING_DEREG`). A Home Deregistration releases the WUID: Roamed does so silently and
Non-Roamed (the home removed the SU from its RID ACL, checked every 5 seconds) also sends U_REG_CMD.
When a roamer moves between two serving RFSSs, the home sends the Roamed Home Deregistration to the
previous one; when both sit behind the same link, the FNE that relays the new registration (the
serving FNE, not the home) sends it instead, so the two messages cannot cross on one link. A home
unit that registers on one of the home's own sites causes the home to send a Roamed Home
Deregistration to its serving system. In the other direction, a home unit that registers at a
serving system is silently released from the home site where it was registered.

The FNE records no unit route for registrations that arrive over an upstream link (upstream routing
is sub-project 3d); the registration itself is still authorized and tracked.

The route the home records for one of its own units served by another system is kept by full SUID
only. Bare Unit ID lookups ignore it: REST and subscriber operation targets (inhibit, check, page,
message), unit-to-unit availability and routing, and unknown-destination flooding treat the unit exactly
as before roaming, so a bare-ID command is never sent to the foreign system, where the same Unit ID may
belong to a different radio. A local registration of the unit replaces the roaming route with the normal
bare route. Routing to a unit served by another system is sub-project 3d.

The FNE REST API lists the home location table (`GET /p25/roaming/locations`) and served roamers
(`GET /p25/roaming/served`) and starts a Forced query (`PUT /p25/roaming/query`, body `netId`,
`sysId` and `unitId` as integers). Errors are reported as a JSON status 400 inside an HTTP 200
response, as for every FNE REST endpoint. A roamer is identified on the network only by its SUID; its
registration and group affiliations are announced with the SUID announcement messages.

## Admission order

1. Different WACN ID: REG_DENY (extended format).
2. Home SU: existing behavior (RID ACL, `requireLLAForReg`, automatic inhibit). A home Unit ID
   inside the roaming pool is answered with REG_REFUSED.
3. Roaming SU:
   - `allowRoaming` false: REG_DENY.
   - System ID `$000`: REG_DENY.
   - System ID not in a non-empty `roamingSysIds`: REG_DENY.
   - Pool exhausted: REG_DENY.
   - Otherwise the home system authorizes the SU (see Home authorization below) and the outcome
     is REG_ACCEPT with the SU's Home System ID, Unit ID, and assigned WUID, REG_DENY, or REG_FAIL.

Roaming SUs are not checked against this site's RID ACL, are never automatically inhibited by this
site's ACL, and are not LLA-authenticated even when `requireLLAForReg` is enabled. The local checks
rely only on the WACN ID and `roamingSysIds`; the home system's RID ACL decides whether the unit is
allowed.

Roaming admission failures deliberately use REG_DENY rather than REG_REFUSED. An SU receiving
REG_REFUSED may enter the "Invalid ID" state and wait for user input (TIA-102.AABD-B 6.4.1.2),
which could strand a public-safety radio on a system that will not serve it. REG_DENY makes the
SU mark the site as denied and resume control channel hunting, so it finds its home system
without user action.

## Current limitations

Roaming SUs are authorized by their home system but are still served locally only until group and
unit-to-unit mobility (sub-projects 3c and 3d) exist:

- Group affiliation, location registration, and de-registration are processed locally. A roamer
  registered through its home is announced to the FNE by SUID (group affiliations name the local
  talkgroup); a roamer admitted unverified (REG_FAIL) is not. These requests also restart the WUID
  validity timer.
- Over-the-air verification across two DVM systems needs a second system configured with its own
  System ID and an APX; until then the in-process multi-FNE harness is the cross-system proof.
- Voice, data, unit-to-unit, telephone interconnect, status, message, call alert, and extended
  function requests are denied with `DENY_SYS_UNSUPPORTED_SVC`.
- Group affiliation requests name the group's own System ID (TIA-102.AABC-D 6.1.9.1). Groups are
  not translated: a roaming SU affiliates to the same-numbered local talkgroup, and the host logs
  the group and site System IDs when they differ.
- PDU-borne SNDCP control data (for example context activation) and conventional data
  registration from a pool WUID are logged as denied. No local SNDCP state is created, nothing is
  forwarded, and no response is sent (both responses are FNE-owned).
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
  registration timer. A requesting SUID's WACN ID or System ID of 0 is echoed as 0. A U_DE_REG_REQ
  carrying the site's WACN ID and System ID with a Unit ID inside the roaming pool is not a roaming
  SU's SUID; it is logged and ignored and never releases a WUID.

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
- With `allowRoaming` enabled, a roaming SU is now authorized by its home system. Without a reachable
  home (no FNE identity, a standalone host, or an FNE link without P25 roaming) it is denied by default;
  set `roamingAllowUnverified: true` to admit it locally, which now answers REG_FAIL (the AABD code for
  unverified local admission) instead of REG_ACCEPT.
- A roaming SU that passes the local checks always receives ACK_RSP_FNE, even with `ackRequests: false`,
  because its answer waits for the home system.

## Subscriber programming

An SU must accept the site's WACN ID and System ID before it transmits on the control channel
(TIA-102.AABD-B 5.4.5). For Motorola APX radios this typically requires an intra-WACN roaming
coverage type, the site control channels in the radio's control channel list, and a NAC/System ID
combination that satisfies the radio's NAC validation setting.
