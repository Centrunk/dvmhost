// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Modem Host Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "common/network/RTPFNEHeader.h"
#include "common/Log.h"
#include "p25/lookups/P25RoamingClient.h"

using namespace p25::lookups;
using namespace network;
using namespace network::roaming;

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the P25RoamingClient class. */

P25RoamingClient::P25RoamingClient(uint32_t homeTimeoutMs) :
    m_mutex(),
    m_homeTimeoutMs((homeTimeoutMs > 0U) ? homeTimeoutMs : ROAM_DEFAULT_HOME_TIMEOUT_MS),
    m_linkDown(false),
    m_pending(),
    m_roamers(),
    m_holdOff(),
    m_random(),
    m_provider(nullptr),
    m_sender(nullptr),
    m_outcome(nullptr),
    m_homeDereg(nullptr),
    m_regCmd(nullptr),
    m_forcedExpiry(nullptr)
{
    std::random_device rd;
    m_random.seed(rd());
}

/* Sets roamingHomeTimeout. */

void P25RoamingClient::setHomeTimeout(uint32_t ms)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_homeTimeoutMs = (ms > 0U) ? ms : ROAM_DEFAULT_HOME_TIMEOUT_MS;
}

/* Gets roamingHomeTimeout. */

uint32_t P25RoamingClient::homeTimeout() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_homeTimeoutMs;
}

/* Sets the callback that fills the serving RFSS identity and reports link capability. */

void P25RoamingClient::setContextProvider(std::function<bool(RfssIdentity&)>&& provider)
{
    m_provider = provider;
}

/* Sets the callback that sends an encoded ROAMING message to the FNE. */

void P25RoamingClient::setSender(std::function<bool(uint8_t, const uint8_t*, uint32_t)>&& sender)
{
    m_sender = sender;
}

/* Sets the callback that applies a Serving Registration outcome on air. */

void P25RoamingClient::setOutcomeCallback(std::function<bool(const SUID&, Outcome, const Profile&, bool)>&& callback)
{
    m_outcome = callback;
}

/* Sets the callback that releases an SU on Home Deregistration. */

void P25RoamingClient::setHomeDeregCallback(std::function<bool(const SUID&, uint8_t)>&& callback)
{
    m_homeDereg = callback;
}

/* Sets the callback that sends U_REG_CMD to an SU's WUID. */

void P25RoamingClient::setRegCmdCallback(std::function<bool(const SUID&)>&& callback)
{
    m_regCmd = callback;
}

/* Sets the callback that releases an SU that did not answer a Forced query. */

void P25RoamingClient::setForcedExpiryCallback(std::function<void(const SUID&)>&& callback)
{
    m_forcedExpiry = callback;
}

/* Requests Serving Registration for a roaming SU. */

P25RoamingClient::RequestResult P25RoamingClient::requestRegistration(const SUID& suid, bool confirmed)
{
    // validate before any lookup; SUID::pack() masks each field, so an out-of-range SUID would alias another SU's key
    if (!suid.valid()) {
        LogError(LOG_P25, "P25 ROAMING, SUID out of range, Serving Registration not sent, suid = $%05X.$%03X.$%06X", suid.netId,
            suid.sysId, suid.unitId);
        return RequestResult::NOT_CAPABLE;
    }

    RfssIdentity serving;
    const bool capable = context(serving);
    const uint64_t key = suid.pack();

    ActionList actions;
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // a registration from the SU answers an outstanding Forced query (spec 4.5)
        if (confirmed) {
            auto roamer = m_roamers.find(key);
            if (roamer != m_roamers.end()) {
                roamer->second.forcedMs = 0U;
            }
        }

        // retries while pending are answered with ACK_RSP_FNE only (spec 4.1 step 3)
        auto pending = m_pending.find(key);
        if (pending != m_pending.end()) {
            if (confirmed) {
                pending->second.onAir = true;
            }
            return RequestResult::PENDING;
        }

        // no new request within RetryTime of a FAILED outcome (spec 4.1 step 8); the marker a deregistration leaves
        //  does not hold off a new request, whose own response then supersedes the abandoned transaction
        auto hold = m_holdOff.find(key);
        if (hold != m_holdOff.end() && hold->second.deregistered) {
            m_holdOff.erase(hold);
        }
        else if (hold != m_holdOff.end()) {
            return RequestResult::HELD_OFF;
        }

        if (!capable) {
            // the next clock() that sees the link capable again resynchronises every held roamer (spec 6)
            m_linkDown = true;
            return RequestResult::NOT_CAPABLE;
        }

        Pending entry;
        entry.suid = suid;
        entry.txnId = nextTxnId();
        entry.onAir = confirmed;
        m_pending[key] = entry;

        RoamingMessage msg;
        msg.subFunc = NET_SUBFUNC::ROAM_SERVING_REG;
        msg.txnId = entry.txnId;
        msg.suid = suid;
        msg.serving = serving;
        msg.presence = confirmed ? RoamPresence::CONFIRMED : RoamPresence::NOT_CONFIRMED;
        LogInfoEx(LOG_P25, "P25 ROAMING, Serving Registration to home, suid = $%05X.$%03X.$%06X, txnId = %08X, presence = %u",
            suid.netId, suid.sysId, suid.unitId, entry.txnId, msg.presence);
        queueSend(actions, msg);
    }

    runActions(actions);
    return RequestResult::SENT;
}

/* Ends a home-registered roamer's registration here and tells the home. */

bool P25RoamingClient::servingDeregistration(const SUID& suid)
{
    if (!suid.valid()) {
        return false;
    }

    const uint64_t key = suid.pack();
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const bool held = m_roamers.erase(key) > 0U;
        auto pending = m_pending.find(key);
        if (pending != m_pending.end()) {
            // the SU leaves before the home answered its first registration: a late success must still be
            //  deregistered, or the home records the SU as served here until expires (spec 4.1 step 9)
            if (!held) {
                HoldOff hold;
                hold.remainingMs = ROAM_RETRY_TIME_MS;
                hold.txnId = pending->second.txnId;
                hold.denied = true;
                hold.deregistered = true;
                m_holdOff[key] = hold;
            }

            m_pending.erase(pending);
        }

        if (!held) {
            return false;
        }
    }

    return sendServingDereg(suid);
}

/* Forgets a roamer without any network message. */

void P25RoamingClient::forget(const SUID& suid)
{
    if (!suid.valid()) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_roamers.erase(suid.pack());
    m_pending.erase(suid.pack());
}

/* Gets whether an SU is registered here through its home. */

bool P25RoamingClient::isRoamer(const SUID& suid) const
{
    if (!suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    return m_roamers.find(suid.pack()) != m_roamers.end();
}

/* Gets whether a Serving Registration is pending. */

bool P25RoamingClient::isPending(const SUID& suid) const
{
    if (!suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending.find(suid.pack()) != m_pending.end();
}

/* Gets whether a roamer's home granted emergency access only. */

bool P25RoamingClient::isEmergencyOnly(const SUID& suid) const
{
    if (!suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_roamers.find(suid.pack());
    return it != m_roamers.end() && it->second.profile.access == RoamAccess::EMERGENCY_ONLY;
}

/* Gets the service profile the home returned for a roamer registered here. */

bool P25RoamingClient::roamerProfile(const SUID& suid, Profile& profile) const
{
    if (!suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_roamers.find(suid.pack());
    if (it == m_roamers.end()) {
        return false;
    }

    profile = it->second.profile;
    return true;
}

/* Gets every roamer registered here through its home. */

std::vector<SUID> P25RoamingClient::roamers() const
{
    std::vector<SUID> list;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& entry : m_roamers) {
        list.push_back(entry.second.suid);
    }
    return list;
}

/* Processes a ROAMING message from the FNE. */

void P25RoamingClient::processMessage(uint8_t subFunc, const uint8_t* data, uint32_t length)
{
    if (data == nullptr || length == 0U) {
        LogWarning(LOG_P25, "P25 ROAMING, malformed message, subFunc = $%02X, dropped", subFunc);
        return;
    }

    // an unknown request is answered GEN_PROC_UNSUPPORTED; an unknown response is dropped (BACA 5.5 Gen Req 4-5)
    if (RoamingCodec::messageLength(subFunc) == 0U) {
        uint8_t version = 0U;
        uint8_t hopCount = 0U;
        uint32_t txnId = 0U;
        if (RoamingCodec::isRequest(subFunc) && RoamingCodec::decodeHeader(data, length, version, hopCount, txnId) == RoamDecode::OK &&
            version == ROAM_VERSION) {
            RoamingMessage rsp;
            rsp.subFunc = NET_SUBFUNC::ROAM_GEN_RSP;
            rsp.txnId = txnId;
            rsp.rejectedSubFunc = subFunc;
            rsp.result = RoamResult::GEN_PROC_UNSUPPORTED;
            ActionList actions;
            queueSend(actions, rsp);
            runActions(actions);
        }
        else {
            LogWarning(LOG_P25, "P25 ROAMING, unknown response or malformed request subFunc = $%02X, length = %u, dropped", subFunc, length);
        }
        return;
    }

    RoamingMessage msg;
    const RoamDecode::E status = RoamingCodec::decode(subFunc, data, length, msg);
    if (status != RoamDecode::OK) {
        LogWarning(LOG_P25, "P25 ROAMING, malformed message, subFunc = $%02X, length = %u, status = %u, dropped", subFunc, length, (uint32_t)status);
        return;
    }

    switch (msg.subFunc) {
    case NET_SUBFUNC::ROAM_SERVING_REG_RSP:
        handleRegResponse(msg, false);
        break;
    case NET_SUBFUNC::ROAM_GEN_RSP:
        if (msg.rejectedSubFunc == NET_SUBFUNC::ROAM_SERVING_REG) {
            handleRegResponse(msg, true);
        }
        break;
    case NET_SUBFUNC::ROAM_SERVING_DEREG_RSP:
        // any response completes a Serving Deregistration (spec 4.3)
        LogInfoEx(LOG_P25, "P25 ROAMING, Serving Deregistration complete, suid = $%05X.$%03X.$%06X, txnId = %08X, result = $%02X",
            msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId, msg.result);
        break;
    case NET_SUBFUNC::ROAM_HOME_DEREG:
        handleHomeDereg(msg);
        break;
    case NET_SUBFUNC::ROAM_QUERY:
        handleQuery(msg);
        break;
    default:
        LogWarning(LOG_P25, "P25 ROAMING, unexpected subFunc = $%02X at a serving host, dropped", msg.subFunc);
        break;
    }
}

/* Updates timers by the passed number of milliseconds. */

void P25RoamingClient::clock(uint32_t ms)
{
    RfssIdentity serving;
    const bool capable = context(serving);

    std::vector<Pending> failed;
    std::vector<SUID> forcedExpired;
    ActionList actions;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // resynchronise only after the link was seen down; a link never seen down needs no resync
        const bool linkRestored = m_linkDown && capable;
        m_linkDown = !capable;

        for (auto it = m_pending.begin(); it != m_pending.end();) {
            it->second.elapsedMs += ms;

            // without a roaming link no response can arrive, so a pending entry completes as FAILED at once (spec 6)
            if (!capable || it->second.elapsedMs >= m_homeTimeoutMs) {
                failed.push_back(it->second);
                it = m_pending.erase(it);
            }
            else {
                ++it;
            }
        }

        for (auto it = m_holdOff.begin(); it != m_holdOff.end();) {
            if (it->second.remainingMs <= ms) {
                it = m_holdOff.erase(it);
            }
            else {
                it->second.remainingMs -= ms;
                ++it;
            }
        }

        for (auto it = m_roamers.begin(); it != m_roamers.end();) {
            Roamer& roamer = it->second;
            if (roamer.forcedMs > 0U) {
                if (roamer.forcedMs <= ms) {
                    // a pending refresh must not re-register an SU that is being deregistered
                    forcedExpired.push_back(roamer.suid);
                    m_pending.erase(it->first);
                    it = m_roamers.erase(it);
                    continue;
                }

                roamer.forcedMs -= ms;
            }

            const bool pending = m_pending.find(it->first) != m_pending.end();
            if (linkRestored && !pending) {
                // on reconnect the host re-registers every roamer it holds (spec 6)
                startRefresh(actions, roamer, serving);
            }
            else {
                roamer.refreshMs = (roamer.refreshMs > ms) ? (roamer.refreshMs - ms) : 0U;
                if (roamer.refreshMs == 0U && !pending) {
                    // the home owns expiry; refresh at 80 % of expires (spec 4.2)
                    if (capable && m_holdOff.find(it->first) == m_holdOff.end()) {
                        startRefresh(actions, roamer, serving);
                    }
                    else {
                        roamer.refreshMs = ROAM_RETRY_TIME_MS;
                    }
                }
            }

            ++it;
        }
    }

    runActions(actions);

    for (const Pending& entry : failed) {
        LogWarning(LOG_P25, "P25 ROAMING, Serving Registration %s, suid = $%05X.$%03X.$%06X, txnId = %08X, FAILED",
            capable ? "timed out" : "lost with the FNE link", entry.suid.netId, entry.suid.sysId, entry.suid.unitId, entry.txnId);
        completeOutcome(entry.suid, entry.txnId, Outcome::FAILED, Profile(), entry.onAir);
    }

    for (const SUID& suid : forcedExpired) {
        LogWarning(LOG_P25, "P25 ROAMING, SU did not re-register after a Forced query, Serving Deregistration, suid = $%05X.$%03X.$%06X",
            suid.netId, suid.sysId, suid.unitId);
        sendServingDereg(suid);
        if (m_forcedExpiry != nullptr) {
            m_forcedExpiry(suid);
        }
    }
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Fills the serving identity and reports link capability. */

bool P25RoamingClient::context(RfssIdentity& serving) const
{
    // a serving identity that cannot be encoded makes the link unusable for roaming
    return m_provider != nullptr && m_provider(serving) && serving.valid();
}

/* Generates a transaction ID. */

uint32_t P25RoamingClient::nextTxnId()
{
    std::uniform_int_distribution<uint32_t> dist(1U, 0xFFFFFFFFU);
    return dist(m_random);
}

/* Gets the refresh period for a lifetime. */

uint32_t P25RoamingClient::refreshPeriodMs(uint32_t expires)
{
    if (expires == 0U) {
        return ROAM_RETRY_TIME_MS;
    }

    const uint64_t period = ((uint64_t)expires * 1000U * ROAM_REFRESH_PERCENT) / 100U;
    return (period > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (uint32_t)period;
}

/* Encodes a message and queues its send. */

void P25RoamingClient::queueSend(ActionList& actions, const RoamingMessage& msg) const
{
    uint8_t buffer[MSG_ROAM_MAX_LEN];
    const uint32_t length = RoamingCodec::encode(msg, buffer, sizeof(buffer));
    if (length == 0U) {
        LogError(LOG_P25, "P25 ROAMING, failed to encode subFunc = $%02X, txnId = %08X", msg.subFunc, msg.txnId);
        return;
    }

    const std::function<bool(uint8_t, const uint8_t*, uint32_t)> sender = m_sender;
    const uint8_t subFunc = msg.subFunc;
    const std::vector<uint8_t> bytes(buffer, buffer + length);
    actions.push_back([sender, subFunc, bytes]() {
        if (sender != nullptr) {
            sender(subFunc, bytes.data(), (uint32_t)bytes.size());
        }
    });
}

/* Starts a Not Confirmed refresh for a roamer. */

void P25RoamingClient::startRefresh(ActionList& actions, Roamer& roamer, const RfssIdentity& serving)
{
    Pending entry;
    entry.suid = roamer.suid;
    entry.txnId = nextTxnId();
    entry.onAir = false;
    m_pending[roamer.suid.pack()] = entry;
    roamer.refreshMs = refreshPeriodMs(roamer.profile.expires);

    RoamingMessage msg;
    msg.subFunc = NET_SUBFUNC::ROAM_SERVING_REG;
    msg.txnId = entry.txnId;
    msg.suid = roamer.suid;
    msg.serving = serving;
    msg.presence = RoamPresence::NOT_CONFIRMED;
    LogInfoEx(LOG_P25, "P25 ROAMING, Serving Registration refresh, suid = $%05X.$%03X.$%06X, txnId = %08X", roamer.suid.netId,
        roamer.suid.sysId, roamer.suid.unitId, entry.txnId);
    queueSend(actions, msg);
}

/* Sends ROAM_SERVING_DEREG without changing roamer state. */

bool P25RoamingClient::sendServingDereg(const SUID& suid)
{
    RfssIdentity serving;
    if (!context(serving)) {
        LogWarning(LOG_P25, "P25 ROAMING, FNE link is not roaming capable, Serving Deregistration not sent, suid = $%05X.$%03X.$%06X",
            suid.netId, suid.sysId, suid.unitId);
        return false;
    }

    ActionList actions;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        RoamingMessage msg;
        msg.subFunc = NET_SUBFUNC::ROAM_SERVING_DEREG;
        msg.txnId = nextTxnId();
        msg.suid = suid;
        msg.serving = serving;
        LogInfoEx(LOG_P25, "P25 ROAMING, Serving Deregistration to home, suid = $%05X.$%03X.$%06X, txnId = %08X", suid.netId, suid.sysId,
            suid.unitId, msg.txnId);
        queueSend(actions, msg);
    }

    runActions(actions);
    return true;
}

/* Delivers an outcome and updates roamer and hold-off state. */

void P25RoamingClient::completeOutcome(const SUID& suid, uint32_t txnId, Outcome outcome, const Profile& profile, bool onAir)
{
    const uint64_t key = suid.pack();
    if (outcome == Outcome::REJECTED) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_roamers.erase(key);
    }

    bool admitted = false;
    if (m_outcome != nullptr) {
        admitted = m_outcome(suid, outcome, profile, onAir);
    }

    if (outcome == Outcome::SUCCESS) {
        if (admitted) {
            std::lock_guard<std::mutex> lock(m_mutex);
            Roamer& roamer = m_roamers[key];
            roamer.suid = suid;
            roamer.profile = profile;
            roamer.refreshMs = refreshPeriodMs(profile.expires);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_roamers.erase(key);
        }

        // the home must not believe the SU is served here (spec 4.1 step 9)
        LogWarning(LOG_P25, "P25 ROAMING, home accepted an SU that is not admitted here, suid = $%05X.$%03X.$%06X", suid.netId, suid.sysId,
            suid.unitId);
        sendServingDereg(suid);
        return;
    }

    if (outcome == Outcome::FAILED) {
        std::lock_guard<std::mutex> lock(m_mutex);
        HoldOff hold;
        hold.remainingMs = ROAM_RETRY_TIME_MS;
        hold.txnId = txnId;

        // a failed refresh keeps the roamer and retries after RetryTime (spec 4.2, 6); a late success for it must not
        //  deregister an SU that is still served here, so only an SU that is not held counts as denied (spec 4.1 step 9)
        auto roamer = m_roamers.find(key);
        if (roamer != m_roamers.end()) {
            roamer->second.refreshMs = ROAM_RETRY_TIME_MS;
        }

        hold.denied = !admitted && roamer == m_roamers.end();
        m_holdOff[key] = hold;
    }
}

/* Handles ROAM_SERVING_REG_RSP or a ROAM_GEN_RSP rejecting ROAM_SERVING_REG. */

void P25RoamingClient::handleRegResponse(const RoamingMessage& msg, bool general)
{
    bool found = false;
    bool onAir = false;
    bool lateDereg = false;
    SUID suid = msg.suid;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_pending.begin(); it != m_pending.end(); ++it) {
            if (it->second.txnId == msg.txnId && (general || it->second.suid == msg.suid)) {
                found = true;
                suid = it->second.suid;
                onAir = it->second.onAir;
                m_pending.erase(it);
                break;
            }
        }

        if (!found && !general && msg.result == RoamResult::SUCCESS) {
            auto hold = m_holdOff.find(msg.suid.pack());
            lateDereg = (hold != m_holdOff.end() && hold->second.txnId == msg.txnId && hold->second.denied);

            // one Serving Deregistration per late success; a duplicate delivery is dropped
            if (lateDereg) {
                hold->second.denied = false;
            }
        }
    }

    if (!found) {
        if (lateDereg) {
            LogWarning(LOG_P25, "P25 ROAMING, late success after the SU was denied, Serving Deregistration, suid = $%05X.$%03X.$%06X, txnId = %08X",
                msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
            sendServingDereg(msg.suid);
        }
        else {
            LogWarning(LOG_P25, "P25 ROAMING, response with unknown or stale txnId = %08X, dropped", msg.txnId);
        }
        return;
    }

    Outcome outcome = Outcome::FAILED;
    Profile profile;
    profile.result = msg.result;
    if (general) {
        outcome = Outcome::REJECTED;
        profile.result = RoamResult::GEN_PROC_UNSUPPORTED;
    }
    else {
        switch (msg.result) {
        case RoamResult::SUCCESS:
            outcome = Outcome::SUCCESS;
            profile.access = msg.access;
            profile.inhibited = (msg.flags & ROAM_FLAG_RADIO_INHIBITED) != 0U;
            profile.expires = msg.expires;
            break;
        case RoamResult::MME_SU_REG_DISALLOWED:
        case RoamResult::MME_MUST_CONFIRM_SU_PRESENCE:
        case RoamResult::GEN_PROC_UNSUPPORTED:
        case RoamResult::MME_SU_UNKNOWN:
        case RoamResult::MME_SU_AUTHEN_REQUIRED:
            outcome = Outcome::REJECTED;
            break;
        default:
            // an unknown result code is treated as FAILED (spec 6)
            LogWarning(LOG_P25, "P25 ROAMING, unknown result $%02X, treated as FAILED, suid = $%05X.$%03X.$%06X", msg.result, suid.netId,
                suid.sysId, suid.unitId);
            outcome = Outcome::FAILED;
            break;
        }
    }

    completeOutcome(suid, msg.txnId, outcome, profile, onAir);
}

/* Handles ROAM_HOME_DEREG. */

void P25RoamingClient::handleHomeDereg(const RoamingMessage& msg)
{
    // forget first so the release sends no Serving Deregistration (spec 4.4)
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        found = m_roamers.erase(msg.suid.pack()) > 0U;
        m_pending.erase(msg.suid.pack());
    }

    // Not Found only when neither the client nor the host holds a record of the SUID (spec 4.4)
    if (m_homeDereg != nullptr && m_homeDereg(msg.suid, msg.qualifier)) {
        found = true;
    }

    LogInfoEx(LOG_P25, "P25 ROAMING, Home Deregistration (%s), suid = $%05X.$%03X.$%06X, txnId = %08X, %s",
        (msg.qualifier == RoamQualifier::NON_ROAMED) ? "Non-Roamed" : "Roamed", msg.suid.netId, msg.suid.sysId, msg.suid.unitId,
        msg.txnId, found ? "released" : "not found");

    RoamingMessage rsp;
    rsp.subFunc = NET_SUBFUNC::ROAM_HOME_DEREG_RSP;
    rsp.txnId = msg.txnId;
    rsp.suid = msg.suid;
    rsp.result = found ? RoamResult::SUCCESS : RoamResult::MME_SU_UNKNOWN;

    ActionList actions;
    queueSend(actions, rsp);
    runActions(actions);
}

/* Handles ROAM_QUERY. */

void P25RoamingClient::handleQuery(const RoamingMessage& msg)
{
    const uint64_t key = msg.suid.pack();
    bool held = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        held = m_roamers.find(key) != m_roamers.end();
    }

    RoamingMessage rsp;
    rsp.subFunc = NET_SUBFUNC::ROAM_QUERY_RSP;
    rsp.txnId = msg.txnId;
    rsp.suid = msg.suid;

    switch (msg.queryType) {
    case RoamQueryType::NORMAL_HOME:
        rsp.result = held ? RoamResult::SUCCESS : RoamResult::MME_SU_UNKNOWN;
        rsp.interested = held ? 1U : 0U;
        break;
    case RoamQueryType::FORCED:
        {
            // the SU is commanded to re-register; no answer within roamingHomeTimeout ends its registration (spec 4.5)
            if (held && m_regCmd != nullptr && m_regCmd(msg.suid)) {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto roamer = m_roamers.find(key);
                if (roamer != m_roamers.end()) {
                    roamer->second.forcedMs = m_homeTimeoutMs;
                }
                rsp.result = RoamResult::SUCCESS;
                rsp.interested = 1U;
            }
            else {
                rsp.result = RoamResult::MME_SU_UNKNOWN;
                rsp.interested = 0U;
            }
        }
        break;
    default:
        // Confirmed and Serving queries are optional and answered unsupported (deviation D4)
        rsp.result = RoamResult::GEN_PROC_UNSUPPORTED;
        rsp.interested = 0U;
        break;
    }

    ActionList actions;
    queueSend(actions, rsp);
    runActions(actions);
}

/* Runs deferred actions. */

void P25RoamingClient::runActions(ActionList& actions)
{
    for (auto& action : actions) {
        action();
    }
    actions.clear();
}
