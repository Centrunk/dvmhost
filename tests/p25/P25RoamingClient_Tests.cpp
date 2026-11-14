// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "host/Defines.h"
#include "common/network/P25Roaming.h"
#include "common/network/RTPFNEHeader.h"
#include "host/p25/lookups/P25RoamingClient.h"

#include <catch2/catch_test_macros.hpp>

#include <utility>
#include <vector>

using namespace network;
using namespace network::roaming;
using namespace p25::lookups;

namespace {
    /**
     * @brief One message the client asked to send.
     */
    struct ClientSend {
        uint8_t subFunc = 0U;                   //!< ROAMING sub-function.
        std::vector<uint8_t> data;              //!< Encoded message.
    };

    /**
     * @brief One outcome callback invocation.
     */
    struct OutcomeCall {
        SUID suid;                              //!< Roaming SUID.
        P25RoamingClient::Outcome outcome = P25RoamingClient::Outcome::FAILED;  //!< Outcome.
        P25RoamingClient::Profile profile;      //!< Service profile.
        bool onAir = false;                     //!< SU waiting for an on-air answer.
    };

    const SUID ROAMER = { 0xBB800U, 0x002U, 1001U };

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief P25RoamingClient with recording callbacks; the site is $BB800.$001 RFSS 1.
     */
    class ClientRig {
    public:
        /**
         * @brief Initializes a new instance of the ClientRig class.
         */
        ClientRig() :
            client(5000U),
            capable(true),
            admit(true),
            regCmdFound(true),
            homeDeregFound(true),
            sends(),
            outcomes(),
            homeDeregs(),
            regCmds(),
            forcedExpired()
        {
            client.setContextProvider([this](RfssIdentity& serving) {
                serving = RfssIdentity{ 0xBB800U, 0x001U, 0x01U };
                return capable;
            });
            client.setSender([this](uint8_t subFunc, const uint8_t* data, uint32_t length) {
                ClientSend send;
                send.subFunc = subFunc;
                send.data.assign(data, data + length);
                sends.push_back(send);
                return true;
            });
            client.setOutcomeCallback([this](const SUID& suid, P25RoamingClient::Outcome outcome, const P25RoamingClient::Profile& profile, bool onAir) {
                OutcomeCall call;
                call.suid = suid;
                call.outcome = outcome;
                call.profile = profile;
                call.onAir = onAir;
                outcomes.push_back(call);
                return admit;
            });
            client.setHomeDeregCallback([this](const SUID& suid, uint8_t qualifier) {
                homeDeregs.push_back(std::make_pair(suid, qualifier));
                return homeDeregFound;
            });
            client.setRegCmdCallback([this](const SUID& suid) {
                regCmds.push_back(suid);
                return regCmdFound;
            });
            client.setForcedExpiryCallback([this](const SUID& suid) { forcedExpired.push_back(suid); });
        }
        ClientRig(const ClientRig&) = delete;
        ClientRig& operator=(const ClientRig&) = delete;

        /**
         * @brief Counts sends of a sub-function.
         * @param subFunc ROAMING sub-function.
         * @returns size_t Count.
         */
        size_t count(uint8_t subFunc) const
        {
            size_t total = 0U;
            for (const ClientSend& send : sends) {
                if (send.subFunc == subFunc) {
                    ++total;
                }
            }
            return total;
        }

        /**
         * @brief Decodes the last send of a sub-function (REQUIREs one exists).
         * @param subFunc ROAMING sub-function.
         * @returns RoamingMessage Decoded message.
         */
        RoamingMessage last(uint8_t subFunc) const
        {
            for (auto it = sends.rbegin(); it != sends.rend(); ++it) {
                if (it->subFunc == subFunc) {
                    RoamingMessage msg;
                    REQUIRE(RoamingCodec::decode(subFunc, it->data.data(), (uint32_t)it->data.size(), msg) == RoamDecode::OK);
                    return msg;
                }
            }
            FAIL("no matching send");
            return RoamingMessage();
        }

        /**
         * @brief Encodes and delivers a message to the client.
         * @param msg Message.
         */
        void deliver(const RoamingMessage& msg)
        {
            uint8_t buffer[MSG_ROAM_MAX_LEN];
            const uint32_t length = RoamingCodec::encode(msg, buffer, sizeof(buffer));
            REQUIRE(length > 0U);
            client.processMessage(msg.subFunc, buffer, length);
        }

        /**
         * @brief Answers the last Serving Registration.
         * @param result Result code.
         * @param access Access value.
         * @param flags Flags.
         */
        void respond(uint8_t result, uint8_t access = RoamAccess::FULL, uint8_t flags = 0x00U)
        {
            const RoamingMessage reg = last(NET_SUBFUNC::ROAM_SERVING_REG);
            RoamingMessage rsp;
            rsp.subFunc = NET_SUBFUNC::ROAM_SERVING_REG_RSP;
            rsp.txnId = reg.txnId;
            rsp.suid = reg.suid;
            rsp.result = result;
            rsp.expires = ROAM_DEFAULT_EXPIRES;
            rsp.access = access;
            rsp.flags = flags;
            deliver(rsp);
        }

        /**
         * @brief Delivers a home-side request.
         * @param subFunc ROAM_HOME_DEREG or ROAM_QUERY.
         * @param suid Subject SUID.
         * @param txnId Transaction ID.
         * @param value Qualifier or query type.
         */
        void request(uint8_t subFunc, const SUID& suid, uint32_t txnId, uint8_t value)
        {
            RoamingMessage msg;
            msg.subFunc = subFunc;
            msg.txnId = txnId;
            msg.suid = suid;
            msg.qualifier = value;
            msg.queryType = value;
            deliver(msg);
        }

        /**
         * @brief Registers ROAMER through a successful home answer.
         */
        void registerRoamer()
        {
            REQUIRE(client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
            respond(RoamResult::SUCCESS);
            REQUIRE(client.isRoamer(ROAMER));
        }

        P25RoamingClient client;
        bool capable;
        bool admit;
        bool regCmdFound;
        bool homeDeregFound;
        std::vector<ClientSend> sends;
        std::vector<OutcomeCall> outcomes;
        std::vector<std::pair<SUID, uint8_t>> homeDeregs;
        std::vector<SUID> regCmds;
        std::vector<SUID> forcedExpired;
    };
} // namespace

TEST_CASE("P25 roaming client Serving Registration outcomes", "[p25][roaming][client]")
{
    ClientRig rig;

    SECTION("Request_Sends_One_Confirmed_Serving_Registration") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        REQUIRE(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        const RoamingMessage reg = rig.last(NET_SUBFUNC::ROAM_SERVING_REG);
        CHECK(reg.hopCount == ROAM_DEFAULT_HOP_COUNT);
        CHECK(reg.suid == ROAMER);
        CHECK(reg.serving == RfssIdentity{ 0xBB800U, 0x001U, 0x01U });
        CHECK(reg.presence == RoamPresence::CONFIRMED);
        CHECK(rig.client.isPending(ROAMER));

        CHECK(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::PENDING);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
    }

    SECTION("Link_Without_Roaming") {
        rig.capable = false;
        CHECK(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::NOT_CAPABLE);
        CHECK(rig.sends.empty());
    }

    SECTION("Unencodable_SUID_Creates_No_Pending_Entry") {
        const SUID bad = { ROAM_MAX_WACN + 1U, 0x002U, 1001U };
        CHECK(rig.client.requestRegistration(bad, true) == P25RoamingClient::RequestResult::NOT_CAPABLE);
        CHECK(rig.sends.empty());
        CHECK_FALSE(rig.client.isPending(bad));
    }

    SECTION("Success_Registers_The_Roamer") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.respond(RoamResult::SUCCESS);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::SUCCESS);
        CHECK(rig.outcomes[0U].onAir);
        CHECK(rig.outcomes[0U].profile.access == RoamAccess::FULL);
        CHECK(rig.outcomes[0U].profile.expires == ROAM_DEFAULT_EXPIRES);
        CHECK_FALSE(rig.outcomes[0U].profile.inhibited);
        CHECK(rig.client.isRoamer(ROAMER));
        CHECK_FALSE(rig.client.isPending(ROAMER));
        CHECK(rig.client.roamers().size() == 1U);
    }

    SECTION("Emergency_Access_And_Radio_Inhibit_Profile") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.respond(RoamResult::SUCCESS, RoamAccess::EMERGENCY_ONLY, ROAM_FLAG_RADIO_INHIBITED);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].profile.access == RoamAccess::EMERGENCY_ONLY);
        CHECK(rig.outcomes[0U].profile.inhibited);
        CHECK(rig.client.isEmergencyOnly(ROAMER));
    }

    SECTION("Known_Failure_Codes_Are_Rejected") {
        const uint8_t codes[5U] = { RoamResult::MME_SU_REG_DISALLOWED, RoamResult::MME_MUST_CONFIRM_SU_PRESENCE,
            RoamResult::GEN_PROC_UNSUPPORTED, RoamResult::MME_SU_UNKNOWN, RoamResult::MME_SU_AUTHEN_REQUIRED };
        uint32_t unitId = 2000U;
        for (uint8_t code : codes) {
            INFO("result " << (uint32_t)code);
            const SUID suid = { 0xBB800U, 0x002U, unitId++ };
            REQUIRE(rig.client.requestRegistration(suid, true) == P25RoamingClient::RequestResult::SENT);
            rig.respond(code);
            REQUIRE_FALSE(rig.outcomes.empty());
            CHECK(rig.outcomes.back().outcome == P25RoamingClient::Outcome::REJECTED);
            CHECK(rig.outcomes.back().profile.result == code);
            CHECK_FALSE(rig.client.isRoamer(suid));
            // a rejection is not FAILED, so no RetryTime hold-off
            CHECK(rig.client.requestRegistration(suid, true) == P25RoamingClient::RequestResult::SENT);
        }
    }

    SECTION("Unknown_Result_Code_Is_FAILED") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.respond(0x99U);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::FAILED);
        CHECK(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::HELD_OFF);
    }

    SECTION("General_Response_Rejecting_The_Request") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        RoamingMessage gen;
        gen.subFunc = NET_SUBFUNC::ROAM_GEN_RSP;
        gen.txnId = rig.last(NET_SUBFUNC::ROAM_SERVING_REG).txnId;
        gen.rejectedSubFunc = NET_SUBFUNC::ROAM_SERVING_REG;
        gen.result = RoamResult::GEN_PROC_UNSUPPORTED;
        rig.deliver(gen);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::REJECTED);
        CHECK(rig.outcomes[0U].profile.result == RoamResult::GEN_PROC_UNSUPPORTED);
    }

    SECTION("Success_Not_Admitted_Sends_Serving_Deregistration") {
        rig.admit = false;
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.respond(RoamResult::SUCCESS, RoamAccess::NONE);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 1U);
        CHECK(rig.last(NET_SUBFUNC::ROAM_SERVING_DEREG).serving == RfssIdentity{ 0xBB800U, 0x001U, 0x01U });
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
    }
}

TEST_CASE("P25 roaming client timeout, hold-off and late responses", "[p25][roaming][client]")
{
    ClientRig rig;

    SECTION("Timeout_Is_FAILED_And_Held_Off_For_RetryTime") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.client.clock(4999U);
        CHECK(rig.outcomes.empty());
        rig.client.clock(1U);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::FAILED);
        CHECK(rig.outcomes[0U].onAir);

        CHECK(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::HELD_OFF);
        rig.client.clock(9999U);
        CHECK(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::HELD_OFF);
        rig.client.clock(1U);
        CHECK(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 2U);
    }

    SECTION("Home_Timeout_Is_Configurable") {
        rig.client.setHomeTimeout(2000U);
        CHECK(rig.client.homeTimeout() == 2000U);
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.client.clock(2000U);
        CHECK(rig.outcomes.size() == 1U);
    }

    SECTION("Late_Success_After_Denial_Sends_Serving_Deregistration") {
        rig.admit = false;
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.client.clock(5000U);
        REQUIRE(rig.outcomes.size() == 1U);
        rig.respond(RoamResult::SUCCESS);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 1U);
        CHECK(rig.outcomes.size() == 1U);

        // a duplicate late success does not send a second Serving Deregistration
        rig.respond(RoamResult::SUCCESS);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 1U);
    }

    SECTION("Deregistration_While_The_First_Registration_Is_Pending_Deregisters_A_Late_Success") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        CHECK_FALSE(rig.client.servingDeregistration(ROAMER));
        CHECK_FALSE(rig.client.isPending(ROAMER));
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);

        // the home's success arrives after the SU left: exactly one Serving Deregistration so the home does not
        //  record the SU as served here for expires
        rig.respond(RoamResult::SUCCESS);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 1U);
        CHECK(rig.last(NET_SUBFUNC::ROAM_SERVING_DEREG).suid == ROAMER);
        CHECK(rig.outcomes.empty());
        CHECK_FALSE(rig.client.isRoamer(ROAMER));

        rig.respond(RoamResult::SUCCESS);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 1U);
    }

    SECTION("Deregistration_While_Pending_Does_Not_Hold_Off_A_New_Registration") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        const RoamingMessage first = rig.last(NET_SUBFUNC::ROAM_SERVING_REG);
        CHECK_FALSE(rig.client.servingDeregistration(ROAMER));

        // the SU registers again at once; the abandoned transaction's success is then stale
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        RoamingMessage stale;
        stale.subFunc = NET_SUBFUNC::ROAM_SERVING_REG_RSP;
        stale.txnId = first.txnId;
        stale.suid = ROAMER;
        stale.result = RoamResult::SUCCESS;
        stale.expires = ROAM_DEFAULT_EXPIRES;
        stale.access = RoamAccess::FULL;
        rig.deliver(stale);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);

        rig.respond(RoamResult::SUCCESS);
        CHECK(rig.client.isRoamer(ROAMER));
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);
    }

    SECTION("Late_Success_After_Local_Admission_Is_Dropped") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.client.clock(5000U);
        rig.respond(RoamResult::SUCCESS);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);
        CHECK(rig.outcomes.size() == 1U);
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
    }
}

TEST_CASE("P25 roaming client refresh and link resynchronisation", "[p25][roaming][client]")
{
    ClientRig rig;
    rig.registerRoamer();
    rig.sends.clear();
    rig.outcomes.clear();

    SECTION("Timer_Refresh_At_80_Percent_Is_Not_Confirmed") {
        // 80 % of 18000 s = 14400 s
        rig.client.clock(14399999U);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 0U);
        rig.client.clock(1U);
        REQUIRE(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        CHECK(rig.last(NET_SUBFUNC::ROAM_SERVING_REG).presence == RoamPresence::NOT_CONFIRMED);

        rig.respond(RoamResult::SUCCESS);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::SUCCESS);
        CHECK_FALSE(rig.outcomes[0U].onAir);
        CHECK(rig.client.isRoamer(ROAMER));
    }

    SECTION("SU_Request_Refresh_Is_Confirmed") {
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        CHECK(rig.last(NET_SUBFUNC::ROAM_SERVING_REG).presence == RoamPresence::CONFIRMED);
    }

    SECTION("Failed_Timer_Refresh_Keeps_The_Roamer_And_Retries_After_RetryTime") {
        rig.client.clock(14400000U);
        REQUIRE(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        rig.client.clock(5000U);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::FAILED);
        CHECK_FALSE(rig.outcomes[0U].onAir);
        CHECK(rig.client.isRoamer(ROAMER));

        rig.client.clock(9999U);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        rig.client.clock(1U);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 2U);
    }

    SECTION("Late_Success_For_Failed_Refresh_Of_Held_Roamer_Is_Dropped") {
        // the host does not admit on FAILED, but the roamer is still held, so a late success must not deregister it
        rig.admit = false;
        rig.client.clock(14400000U);
        REQUIRE(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        rig.client.clock(5000U);
        REQUIRE(rig.outcomes.size() == 1U);
        rig.respond(RoamResult::SUCCESS);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);
        CHECK(rig.outcomes.size() == 1U);
        CHECK(rig.client.isRoamer(ROAMER));
    }

    SECTION("Link_Loss_Fails_Pending_And_Restore_Resynchronises") {
        const SUID other = { 0xBB800U, 0x002U, 1002U };
        REQUIRE(rig.client.requestRegistration(other, true) == P25RoamingClient::RequestResult::SENT);
        rig.capable = false;
        rig.client.clock(1U);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].suid == other);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::FAILED);
        CHECK(rig.client.isRoamer(ROAMER));

        rig.sends.clear();
        rig.capable = true;
        rig.client.clock(1U);
        REQUIRE(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        const RoamingMessage resync = rig.last(NET_SUBFUNC::ROAM_SERVING_REG);
        CHECK(resync.suid == ROAMER);
        CHECK(resync.presence == RoamPresence::NOT_CONFIRMED);
    }

    SECTION("SU_Request_Between_Restore_And_Clock_Does_Not_Skip_Resynchronisation") {
        rig.capable = false;
        rig.client.clock(1U);
        rig.capable = true;
        const SUID other = { 0xBB800U, 0x002U, 1003U };
        REQUIRE(rig.client.requestRegistration(other, true) == P25RoamingClient::RequestResult::SENT);

        rig.sends.clear();
        rig.client.clock(1U);
        REQUIRE(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        const RoamingMessage resync = rig.last(NET_SUBFUNC::ROAM_SERVING_REG);
        CHECK(resync.suid == ROAMER);
        CHECK(resync.presence == RoamPresence::NOT_CONFIRMED);
    }

    SECTION("Pending_Fails_On_Any_Clock_Without_A_Roaming_Link") {
        rig.capable = false;
        rig.client.clock(1U);
        rig.capable = true;
        const SUID other = { 0xBB800U, 0x002U, 1004U };
        REQUIRE(rig.client.requestRegistration(other, true) == P25RoamingClient::RequestResult::SENT);

        rig.capable = false;
        rig.client.clock(1U);
        REQUIRE(rig.outcomes.size() == 1U);
        CHECK(rig.outcomes[0U].suid == other);
        CHECK(rig.outcomes[0U].outcome == P25RoamingClient::Outcome::FAILED);
        CHECK_FALSE(rig.client.isPending(other));
    }
}

TEST_CASE("P25 roaming client Home Deregistration, Query and Serving Deregistration", "[p25][roaming][client]")
{
    ClientRig rig;
    rig.registerRoamer();
    rig.sends.clear();

    SECTION("Home_Deregistration_Roamed") {
        rig.request(NET_SUBFUNC::ROAM_HOME_DEREG, ROAMER, 0x77U, RoamQualifier::ROAMED);
        REQUIRE(rig.homeDeregs.size() == 1U);
        CHECK(rig.homeDeregs[0U].second == RoamQualifier::ROAMED);
        const RoamingMessage rsp = rig.last(NET_SUBFUNC::ROAM_HOME_DEREG_RSP);
        CHECK(rsp.txnId == 0x77U);
        CHECK(rsp.result == RoamResult::SUCCESS);
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);
    }

    SECTION("Home_Deregistration_Of_A_Client_Roamer_Is_Success") {
        // the client's own roamer record is a record of the SUID even when the host callback finds none
        rig.homeDeregFound = false;
        rig.request(NET_SUBFUNC::ROAM_HOME_DEREG, ROAMER, 0x76U, RoamQualifier::ROAMED);
        CHECK(rig.last(NET_SUBFUNC::ROAM_HOME_DEREG_RSP).result == RoamResult::SUCCESS);
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
    }

    SECTION("Forced_Expiry_Abandons_A_Pending_Refresh") {
        rig.request(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x7FU, RoamQueryType::FORCED);
        rig.capable = false;
        rig.client.clock(1000U);
        rig.capable = true;
        rig.client.clock(1U);
        REQUIRE(rig.count(NET_SUBFUNC::ROAM_SERVING_REG) == 1U);
        REQUIRE(rig.client.isPending(ROAMER));

        rig.client.clock(3999U);
        REQUIRE(rig.forcedExpired.size() == 1U);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 1U);
        CHECK_FALSE(rig.client.isPending(ROAMER));

        // the refresh answer arrives after the deregistration and must not re-register the SU
        rig.respond(RoamResult::SUCCESS);
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
        CHECK(rig.outcomes.size() == 1U);
    }

    SECTION("Out_Of_Range_SUID_Does_Not_Alias_A_Held_SU") {
        // SUID::pack() masks each field, so this SUID packs to ROAMER's key
        const SUID alias = { ROAMER.netId | (ROAM_MAX_WACN + 1U), ROAMER.sysId, ROAMER.unitId };
        REQUIRE(alias.pack() == ROAMER.pack());

        rig.request(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x80U, RoamQueryType::FORCED);
        CHECK(rig.client.requestRegistration(alias, true) == P25RoamingClient::RequestResult::NOT_CAPABLE);
        CHECK_FALSE(rig.client.isRoamer(alias));
        CHECK_FALSE(rig.client.isPending(alias));
        CHECK_FALSE(rig.client.isEmergencyOnly(alias));
        CHECK_FALSE(rig.client.servingDeregistration(alias));
        rig.client.forget(alias);
        CHECK(rig.client.isRoamer(ROAMER));
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);

        // the Forced-query timer was not reset by the alias, so ROAMER is still deregistered on time
        rig.client.clock(5000U);
        CHECK(rig.forcedExpired.size() == 1U);
    }

    SECTION("Out_Of_Range_SUID_Does_Not_Alias_A_Pending_SU") {
        const SUID alias = { ROAMER.netId, ROAMER.sysId | (ROAM_MAX_SYSID + 1U), ROAMER.unitId };
        REQUIRE(alias.pack() == ROAMER.pack());

        REQUIRE(rig.client.requestRegistration(ROAMER, false) == P25RoamingClient::RequestResult::SENT);
        CHECK(rig.client.requestRegistration(alias, true) == P25RoamingClient::RequestResult::NOT_CAPABLE);
        rig.respond(RoamResult::SUCCESS);
        REQUIRE_FALSE(rig.outcomes.empty());
        CHECK(rig.outcomes.back().outcome == P25RoamingClient::Outcome::SUCCESS);
        CHECK_FALSE(rig.outcomes.back().onAir);
    }

    SECTION("Home_Deregistration_Not_Found") {
        rig.homeDeregFound = false;
        rig.request(NET_SUBFUNC::ROAM_HOME_DEREG, SUID{ 0xBB800U, 0x002U, 99U }, 0x78U, RoamQualifier::NON_ROAMED);
        CHECK(rig.last(NET_SUBFUNC::ROAM_HOME_DEREG_RSP).result == RoamResult::MME_SU_UNKNOWN);
    }

    SECTION("Normal_Query") {
        rig.request(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x79U, RoamQueryType::NORMAL_HOME);
        RoamingMessage rsp = rig.last(NET_SUBFUNC::ROAM_QUERY_RSP);
        CHECK(rsp.result == RoamResult::SUCCESS);
        CHECK(rsp.interested == 1U);

        rig.request(NET_SUBFUNC::ROAM_QUERY, SUID{ 0xBB800U, 0x002U, 99U }, 0x7AU, RoamQueryType::NORMAL_HOME);
        rsp = rig.last(NET_SUBFUNC::ROAM_QUERY_RSP);
        CHECK(rsp.result == RoamResult::MME_SU_UNKNOWN);
        CHECK(rsp.interested == 0U);
    }

    SECTION("Forced_Query_Without_Reregistration_Deregisters") {
        rig.request(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x7BU, RoamQueryType::FORCED);
        CHECK(rig.regCmds.size() == 1U);
        CHECK(rig.last(NET_SUBFUNC::ROAM_QUERY_RSP).interested == 1U);
        rig.client.clock(4999U);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);
        rig.client.clock(1U);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 1U);
        REQUIRE(rig.forcedExpired.size() == 1U);
        CHECK(rig.forcedExpired[0U] == ROAMER);
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
    }

    SECTION("Forced_Query_Answered_By_Reregistration") {
        rig.request(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x7CU, RoamQueryType::FORCED);
        REQUIRE(rig.client.requestRegistration(ROAMER, true) == P25RoamingClient::RequestResult::SENT);
        rig.respond(RoamResult::SUCCESS);
        rig.client.clock(5000U);
        CHECK(rig.count(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0U);
        CHECK(rig.forcedExpired.empty());
        CHECK(rig.client.isRoamer(ROAMER));
    }

    SECTION("Confirmed_And_Serving_Queries_Are_Unsupported") {
        rig.request(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x7DU, RoamQueryType::CONFIRMED);
        CHECK(rig.last(NET_SUBFUNC::ROAM_QUERY_RSP).result == RoamResult::GEN_PROC_UNSUPPORTED);
        rig.request(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x7EU, RoamQueryType::SERVING);
        CHECK(rig.last(NET_SUBFUNC::ROAM_QUERY_RSP).result == RoamResult::GEN_PROC_UNSUPPORTED);
    }

    SECTION("Serving_Deregistration_And_Forget") {
        CHECK(rig.client.servingDeregistration(ROAMER));
        const RoamingMessage dereg = rig.last(NET_SUBFUNC::ROAM_SERVING_DEREG);
        CHECK(dereg.suid == ROAMER);
        CHECK(dereg.serving == RfssIdentity{ 0xBB800U, 0x001U, 0x01U });
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
        CHECK_FALSE(rig.client.servingDeregistration(ROAMER));

        rig.registerRoamer();
        rig.sends.clear();
        rig.client.forget(ROAMER);
        CHECK_FALSE(rig.client.isRoamer(ROAMER));
        CHECK(rig.sends.empty());
    }

    SECTION("Unknown_Request_And_Malformed_Messages") {
        const uint8_t header[6U] = { 0x01U, 0x08U, 0x00U, 0x00U, 0x00U, 0x42U };
        rig.client.processMessage(0x10U, header, sizeof(header));
        const RoamingMessage gen = rig.last(NET_SUBFUNC::ROAM_GEN_RSP);
        CHECK(gen.rejectedSubFunc == 0x10U);
        CHECK(gen.result == RoamResult::GEN_PROC_UNSUPPORTED);
        CHECK(gen.txnId == 0x42U);

        rig.sends.clear();
        rig.client.processMessage(0x11U, header, sizeof(header));
        const uint8_t shortRsp[20U] = { 0x01U };
        rig.client.processMessage(NET_SUBFUNC::ROAM_SERVING_REG_RSP, shortRsp, sizeof(shortRsp));
        CHECK(rig.sends.empty());
    }
}
