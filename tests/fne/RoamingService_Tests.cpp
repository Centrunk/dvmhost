// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */

#include <catch2/catch_test_macros.hpp>

#include "fne/network/RoamingService.h"
#include "common/network/P25Roaming.h"
#include "common/network/RTPFNEHeader.h"

#include <cstring>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace network;
using namespace network::roaming;

namespace {
    /**
     * @brief One message the RoamingService asked its host to send.
     */
    struct SentMessage {
        RoamingLink link;                       //!< Destination link.
        uint8_t subFunc = 0U;                   //!< ROAMING sub-function.
        std::vector<uint8_t> data;              //!< Encoded message.
    };

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Records everything the RoamingService asks of its host.
     */
    class FakeRoamingHost : public RoamingServiceHost {
    public:
        /**
         * @brief Records a send.
         * @param link Destination link.
         * @param subFunc ROAMING sub-function.
         * @param data Encoded message.
         * @param length Message length.
         * @returns bool Always true.
         */
        bool sendRoaming(const RoamingLink& link, uint8_t subFunc, const uint8_t* data, uint32_t length) override
        {
            SentMessage sentMessage;
            sentMessage.link = link;
            sentMessage.subFunc = subFunc;
            sentMessage.data.assign(data, data + length);
            sent.push_back(sentMessage);
            return true;
        }
        /**
         * @brief Answers from the authorized set.
         * @param unitId Home Unit ID.
         * @returns bool True if authorized.
         */
        bool isHomeUnitAuthorized(uint32_t unitId) override { return authorized.count(unitId) > 0U; }
        /**
         * @brief Answers from the local registration map.
         * @param unitId Home Unit ID.
         * @returns uint32_t Home site peer ID or 0.
         */
        uint32_t findLocalUnitPeer(uint32_t unitId) override
        {
            auto it = localPeers.find(unitId);
            return (it == localPeers.end()) ? 0U : it->second;
        }
        /**
         * @brief Records a local registration removal.
         * @param peerId Home site peer ID.
         * @param unitId Home Unit ID.
         */
        void removeLocalUnitRegistration(uint32_t peerId, uint32_t unitId) override
        {
            removedLocal.push_back(std::make_pair(peerId, unitId));
            localPeers.erase(unitId);
        }
        /**
         * @brief Records a route.
         * @param suid Subscriber SUID.
         * @param link Next-hop link.
         */
        void setUnitRoute(const SUID& suid, const RoamingLink& link) override { routes[suid.pack()] = link; }
        /**
         * @brief Removes a route owned by the link.
         * @param suid Subscriber SUID.
         * @param link Next-hop link.
         */
        void eraseUnitRoute(const SUID& suid, const RoamingLink& link) override
        {
            auto it = routes.find(suid.pack());
            if (it != routes.end() && it->second == link) {
                routes.erase(it);
            }
        }

        std::vector<SentMessage> sent;
        std::set<uint32_t> authorized;
        std::unordered_map<uint32_t, uint32_t> localPeers;
        std::vector<std::pair<uint32_t, uint32_t>> removedLocal;
        std::unordered_map<uint64_t, RoamingLink> routes;
    };

    // ---------------------------------------------------------------------------
    //  Global Functions
    // ---------------------------------------------------------------------------

    const RoamingLink HOST_LINK = { 1001U, false };
    const RoamingLink FNE_A = { 2001U, false };
    const RoamingLink FNE_B = { 2002U, false };
    const RoamingLink UPSTREAM = { 3001U, true };
    const RoamingLink HOME_SITE = { 501U, false };
    const SUID ROAMER = { 0xDEE00U, 0x911U, 0x0F4240U };
    const RfssIdentity SERVING_13B = { 0xDEE00U, 0x13BU, 0x01U };
    const RfssIdentity SERVING_222 = { 0xDEE00U, 0x222U, 0x01U };

    /**
     * @brief Encodes a message (REQUIREs success).
     * @param msg Message.
     * @returns std::vector<uint8_t> Encoded bytes.
     */
    std::vector<uint8_t> encode(const RoamingMessage& msg)
    {
        uint8_t buffer[MSG_ROAM_MAX_LEN];
        const uint32_t length = RoamingCodec::encode(msg, buffer, sizeof(buffer));
        REQUIRE(length > 0U);
        return std::vector<uint8_t>(buffer, buffer + length);
    }

    /**
     * @brief Decodes a captured send (REQUIREs success).
     * @param sent Captured send.
     * @returns RoamingMessage Decoded message.
     */
    RoamingMessage decodeSent(const SentMessage& sent)
    {
        RoamingMessage msg;
        REQUIRE(RoamingCodec::decode(sent.subFunc, sent.data.data(), (uint32_t)sent.data.size(), msg) == RoamDecode::OK);
        return msg;
    }

    /**
     * @brief Builds a ROAM_SERVING_REG.
     * @param suid Roaming SUID.
     * @param serving Serving RFSS.
     * @param txnId Transaction ID.
     * @param hopCount Hop count.
     * @returns RoamingMessage Message.
     */
    RoamingMessage servingReg(const SUID& suid, const RfssIdentity& serving, uint32_t txnId, uint8_t hopCount = ROAM_DEFAULT_HOP_COUNT)
    {
        RoamingMessage msg;
        msg.subFunc = NET_SUBFUNC::ROAM_SERVING_REG;
        msg.hopCount = hopCount;
        msg.txnId = txnId;
        msg.suid = suid;
        msg.serving = serving;
        msg.presence = RoamPresence::CONFIRMED;
        return msg;
    }

    /**
     * @brief Builds a ROAM_SERVING_DEREG.
     * @param suid Roaming SUID.
     * @param serving Serving RFSS.
     * @param txnId Transaction ID.
     * @returns RoamingMessage Message.
     */
    RoamingMessage servingDereg(const SUID& suid, const RfssIdentity& serving, uint32_t txnId)
    {
        RoamingMessage msg;
        msg.subFunc = NET_SUBFUNC::ROAM_SERVING_DEREG;
        msg.txnId = txnId;
        msg.suid = suid;
        msg.serving = serving;
        return msg;
    }

    /**
     * @brief Builds a response or a home-side request carrying a result/qualifier/type byte.
     * @param subFunc ROAMING sub-function.
     * @param suid Subject SUID.
     * @param txnId Transaction ID.
     * @param value Result (responses), qualifier (HOME_DEREG) or query type (QUERY).
     * @returns RoamingMessage Message.
     */
    RoamingMessage simple(uint8_t subFunc, const SUID& suid, uint32_t txnId, uint8_t value)
    {
        RoamingMessage msg;
        msg.subFunc = subFunc;
        msg.txnId = txnId;
        msg.suid = suid;
        msg.result = value;
        msg.qualifier = value;
        msg.queryType = value;
        if (subFunc == NET_SUBFUNC::ROAM_SERVING_REG_RSP && value == RoamResult::SUCCESS) {
            msg.expires = ROAM_DEFAULT_EXPIRES;
            msg.access = RoamAccess::FULL;
        }
        return msg;
    }

    /**
     * @brief Encodes and delivers a message to the service.
     * @param service Roaming service.
     * @param from Ingress link.
     * @param msg Message.
     * @param nowMs Current time in milliseconds.
     */
    void deliver(RoamingService& service, const RoamingLink& from, const RoamingMessage& msg, uint64_t nowMs)
    {
        const std::vector<uint8_t> bytes = encode(msg);
        service.process(from, msg.subFunc, bytes.data(), (uint32_t)bytes.size(), nowMs);
    }

    /**
     * @brief Counts captured sends of a sub-function to a link.
     * @param host Fake host.
     * @param link Destination link.
     * @param subFunc ROAMING sub-function.
     * @returns size_t Count.
     */
    size_t countSent(const FakeRoamingHost& host, const RoamingLink& link, uint8_t subFunc)
    {
        size_t count = 0U;
        for (const SentMessage& sent : host.sent) {
            if (sent.link == link && sent.subFunc == subFunc) {
                ++count;
            }
        }
        return count;
    }

    /**
     * @brief Finds the last captured send of a sub-function to a link (REQUIREs it exists).
     * @param host Fake host.
     * @param link Destination link.
     * @param subFunc ROAMING sub-function.
     * @returns RoamingMessage Decoded message.
     */
    RoamingMessage lastSent(const FakeRoamingHost& host, const RoamingLink& link, uint8_t subFunc)
    {
        for (auto it = host.sent.rbegin(); it != host.sent.rend(); ++it) {
            if (it->link == link && it->subFunc == subFunc) {
                return decodeSent(*it);
            }
        }
        FAIL("no matching send");
        return RoamingMessage();
    }

    /**
     * @brief Delivers, in capture order, every send a fake host made on one link to another service and removes those
     *  sends from the capture.
     * @param from Fake host whose captured sends are delivered.
     * @param egress Link the sends were made on.
     * @param to Receiving service.
     * @param ingress Link on which the receiving service sees them arrive.
     * @param nowMs Current time in milliseconds.
     * @returns size_t Number of messages delivered.
     */
    size_t pump(FakeRoamingHost& from, const RoamingLink& egress, RoamingService& to, const RoamingLink& ingress, uint64_t nowMs)
    {
        std::vector<SentMessage> moving;
        for (auto it = from.sent.begin(); it != from.sent.end();) {
            if (it->link == egress) {
                moving.push_back(*it);
                it = from.sent.erase(it);
            }
            else {
                ++it;
            }
        }

        for (const SentMessage& sent : moving) {
            to.process(ingress, sent.subFunc, sent.data.data(), (uint32_t)sent.data.size(), nowMs);
        }

        return moving.size();
    }
} // namespace

TEST_CASE("RoamingService treats an FNE link carrying this system's own identity as not roaming capable", "[fne][roaming][service][link]")
{
    // exactly one FNE per system holds the identity; a second FNE of the same system on either side of a link is ignored
    FakeRoamingHost host;
    RoamingService service(&host);
    service.setIdentity(0xDEE00U, 0x911U, ROAM_DEFAULT_EXPIRES);
    host.authorized.insert(0x0F4240U);

    service.linkUp(UPSTREAM, true, true, 0xDEE00U, 0x911U);
    service.linkUp(FNE_A, true, true, 0xDEE00U, 0x911U);
    CHECK_FALSE(service.isLinkCapable(UPSTREAM));
    CHECK_FALSE(service.isLinkCapable(FNE_A));

    deliver(service, FNE_A, servingReg(ROAMER, SERVING_13B, 0x5001U), 0U);
    CHECK(host.sent.empty());
    CHECK(service.homeRecords().empty());

    // a host of this system is not an FNE and stays capable
    service.linkUp(HOST_LINK, true, false, 0xDEE00U, 0x911U);
    CHECK(service.isLinkCapable(HOST_LINK));
}

TEST_CASE("RoamingService routes Serving Registration toward the home system", "[fne][roaming][service][routing]")
{
    FakeRoamingHost host;
    RoamingService service(&host);
    service.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    service.linkUp(HOST_LINK, true, false, 0xDEE00U, 0x13BU);
    service.linkUp(FNE_A, true, true, 0xDEE00U, 0x911U);
    service.linkUp(UPSTREAM, true, true, 0xDEE00U, 0x500U);
    const SUID other = { 0xDEE00U, 0x777U, 5U };

    SECTION("Known_System_Is_Forwarded_With_A_Decremented_Hop_Count") {
        deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x1001U), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == FNE_A);
        const RoamingMessage fwd = decodeSent(host.sent[0U]);
        CHECK(fwd.hopCount == 7U);
        CHECK(fwd.txnId == 0x1001U);
        CHECK(fwd.suid == ROAMER);
        CHECK(fwd.serving == SERVING_13B);
        CHECK(service.pendingCount() == 1U);
    }

    SECTION("Unknown_System_Uses_The_Upstream_Default") {
        deliver(service, HOST_LINK, servingReg(other, SERVING_13B, 0x1002U), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == UPSTREAM);
    }

    SECTION("Never_Forwarded_Out_The_Ingress_Link") {
        deliver(service, UPSTREAM, servingReg(other, SERVING_13B, 0x1003U), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == UPSTREAM);
        const RoamingMessage rsp = decodeSent(host.sent[0U]);
        CHECK(rsp.subFunc == NET_SUBFUNC::ROAM_SERVING_REG_RSP);
        CHECK(rsp.result == RoamResult::MME_SU_UNKNOWN);
        CHECK(rsp.txnId == 0x1003U);
        CHECK(service.pendingCount() == 0U);
    }

    SECTION("Hop_Count_Limit") {
        deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x1004U, 1U), 0U);
        deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x1005U, 0U), 0U);
        CHECK(host.sent.empty());
        CHECK(service.pendingCount() == 0U);
    }

    SECTION("Links_That_Did_Not_Negotiate_Roaming_Are_Ignored") {
        const RoamingLink oldHost = { 1002U, false };
        service.linkUp(oldHost, false, false, 0U, 0U);
        deliver(service, oldHost, servingReg(ROAMER, SERVING_13B, 0x1006U), 0U);
        const RoamingLink unknown = { 1003U, false };
        deliver(service, unknown, servingReg(ROAMER, SERVING_13B, 0x1007U), 0U);
        CHECK(host.sent.empty());
    }

    SECTION("No_Route_From_A_Host_Completes_As_FAILED_Without_A_Reply") {
        service.linkDown(UPSTREAM);
        deliver(service, HOST_LINK, servingReg(other, SERVING_13B, 0x1008U), 0U);
        CHECK(host.sent.empty());
        CHECK(service.pendingCount() == 0U);
    }

    SECTION("Disabled_Service_Drops_Everything") {
        service.setIdentity(0U, 0U, ROAM_DEFAULT_EXPIRES);
        CHECK_FALSE(service.enabled());
        deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x1009U), 0U);
        CHECK(host.sent.empty());
    }
}

TEST_CASE("RoamingService relays responses and records served roamers", "[fne][roaming][service][routing]")
{
    FakeRoamingHost host;
    RoamingService service(&host);
    service.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    service.linkUp(HOST_LINK, true, false, 0xDEE00U, 0x13BU);
    service.linkUp(FNE_A, true, true, 0xDEE00U, 0x911U);
    service.linkUp(UPSTREAM, true, true, 0xDEE00U, 0x500U);

    deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x1101U), 0U);
    REQUIRE(host.sent.size() == 1U);

    SECTION("Success_Is_Relayed_And_Recorded") {
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x1101U, RoamResult::SUCCESS), 0U);
        REQUIRE(host.sent.size() == 2U);
        CHECK(host.sent[1U].link == HOST_LINK);
        const RoamingMessage rsp = decodeSent(host.sent[1U]);
        CHECK(rsp.hopCount == 7U);
        CHECK(rsp.result == RoamResult::SUCCESS);
        CHECK(rsp.expires == ROAM_DEFAULT_EXPIRES);
        REQUIRE(service.servingRecords().size() == 1U);
        CHECK(service.servingRecords()[0U].link == HOST_LINK);
        CHECK(service.pendingCount() == 0U);

        // a repeated response is stale
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x1101U, RoamResult::SUCCESS), 0U);
        CHECK(host.sent.size() == 2U);
    }

    SECTION("Failure_Is_Relayed_Without_A_Served_Record") {
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x1101U, RoamResult::MME_SU_UNKNOWN), 0U);
        REQUIRE(host.sent.size() == 2U);
        CHECK(decodeSent(host.sent[1U]).result == RoamResult::MME_SU_UNKNOWN);
        CHECK(service.servingRecords().empty());
    }

    SECTION("Response_From_Another_Link_Or_With_Another_Transaction_Is_Dropped") {
        deliver(service, UPSTREAM, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x1101U, RoamResult::SUCCESS), 0U);
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x9999U, RoamResult::SUCCESS), 0U);
        CHECK(host.sent.size() == 1U);
        CHECK(service.pendingCount() == 1U);
    }

    SECTION("General_Response_Naming_The_Request_Is_Relayed") {
        RoamingMessage gen;
        gen.subFunc = NET_SUBFUNC::ROAM_GEN_RSP;
        gen.txnId = 0x1101U;
        gen.rejectedSubFunc = NET_SUBFUNC::ROAM_SERVING_REG;
        gen.result = RoamResult::GEN_PROC_UNSUPPORTED;
        deliver(service, FNE_A, gen, 0U);
        REQUIRE(host.sent.size() == 2U);
        CHECK(host.sent[1U].link == HOST_LINK);
        CHECK(host.sent[1U].subFunc == NET_SUBFUNC::ROAM_GEN_RSP);
    }

    SECTION("Response_With_An_Exhausted_Hop_Count_Is_Not_Relayed_Or_Recorded") {
        RoamingMessage rsp = simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x1101U, RoamResult::SUCCESS);
        rsp.hopCount = 1U;
        deliver(service, FNE_A, rsp, 0U);
        CHECK(host.sent.size() == 1U);
        CHECK(service.servingRecords().empty());
        CHECK(service.pendingCount() == 0U);
    }
}

TEST_CASE("RoamingService answers unknown requests and drops malformed messages", "[fne][roaming][service][malformed]")
{
    FakeRoamingHost host;
    RoamingService service(&host);
    service.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    service.linkUp(FNE_A, true, true, 0xDEE00U, 0x911U);

    const uint8_t header[6U] = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U };
    service.process(FNE_A, 0x10U, header, sizeof(header), 0U);
    REQUIRE(host.sent.size() == 1U);
    const RoamingMessage gen = decodeSent(host.sent[0U]);
    CHECK(gen.subFunc == NET_SUBFUNC::ROAM_GEN_RSP);
    CHECK(gen.txnId == 0x12345678U);
    CHECK(gen.rejectedSubFunc == 0x10U);
    CHECK(gen.result == RoamResult::GEN_PROC_UNSUPPORTED);

    // an unknown response, a truncated request, an out-of-range WACN and a bad version are dropped
    service.process(FNE_A, 0x11U, header, sizeof(header), 0U);
    std::vector<uint8_t> reg = encode(servingReg(ROAMER, SERVING_13B, 0x1201U));
    service.process(FNE_A, NET_SUBFUNC::ROAM_SERVING_REG, reg.data(), (uint32_t)reg.size() - 1U, 0U);
    std::vector<uint8_t> badWacn = reg;
    badWacn[6U] = 0x10U;
    service.process(FNE_A, NET_SUBFUNC::ROAM_SERVING_REG, badWacn.data(), (uint32_t)badWacn.size(), 0U);
    std::vector<uint8_t> badVersion = reg;
    badVersion[0U] = 0x02U;
    service.process(FNE_A, NET_SUBFUNC::ROAM_SERVING_REG, badVersion.data(), (uint32_t)badVersion.size(), 0U);
    CHECK(host.sent.size() == 1U);
    CHECK(service.pendingCount() == 0U);
}

TEST_CASE("RoamingService home procedures", "[fne][roaming][service][home]")
{
    FakeRoamingHost host;
    RoamingService home(&host);
    home.setIdentity(0xDEE00U, 0x911U, ROAM_DEFAULT_EXPIRES);
    home.linkUp(FNE_A, true, true, 0xDEE00U, 0x13BU);
    home.linkUp(FNE_B, true, true, 0xDEE00U, 0x222U);
    home.linkUp(HOME_SITE, true, false, 0xDEE00U, 0x911U);
    host.authorized.insert(0x0F4240U);

    SECTION("Authorized_Unit_Is_Accepted_And_Routed") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2001U), 1000U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == FNE_A);
        const RoamingMessage rsp = decodeSent(host.sent[0U]);
        CHECK(rsp.subFunc == NET_SUBFUNC::ROAM_SERVING_REG_RSP);
        CHECK(rsp.hopCount == ROAM_DEFAULT_HOP_COUNT);
        CHECK(rsp.txnId == 0x2001U);
        CHECK(rsp.result == RoamResult::SUCCESS);
        CHECK(rsp.expires == 18000U);
        CHECK(rsp.access == RoamAccess::FULL);
        CHECK(rsp.flags == 0x00U);
        REQUIRE(host.routes.count(ROAMER.pack()) == 1U);
        CHECK(host.routes[ROAMER.pack()] == FNE_A);
        REQUIRE(home.homeRecords().size() == 1U);
        CHECK(home.homeRecords()[0U].serving == SERVING_13B);
        CHECK(home.homeRecords()[0U].expiresAtMs == 1000U + 18000000U);
    }

    SECTION("Unknown_Or_Disabled_Unit_Is_MME_SU_UNKNOWN") {
        const SUID unknown = { 0xDEE00U, 0x911U, 99U };
        deliver(home, FNE_A, servingReg(unknown, SERVING_13B, 0x2002U), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(decodeSent(host.sent[0U]).result == RoamResult::MME_SU_UNKNOWN);
        CHECK(home.homeRecords().empty());
        CHECK(host.routes.empty());
    }

    SECTION("Duplicate_Request_Is_Idempotent") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2003U), 0U);
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2003U), 10U);
        REQUIRE(host.sent.size() == 2U);
        CHECK(host.sent[0U].data == host.sent[1U].data);
        CHECK(home.homeRecords().size() == 1U);
        CHECK(home.homeRecords()[0U].expiresAtMs == 18000000U);
        CHECK(countSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG) == 0U);
    }

    SECTION("Refresh_From_The_Same_Serving_RFSS_Sends_No_Home_Deregistration") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2004U), 0U);
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2005U), 5000U);
        CHECK(countSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP) == 2U);
        CHECK(countSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG) == 0U);
        CHECK(home.homeRecords()[0U].expiresAtMs == 5000U + 18000000U);
    }

    SECTION("Move_Sends_Roamed_Home_Deregistration_To_The_Previous_Serving_RFSS") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2006U), 0U);
        deliver(home, FNE_B, servingReg(ROAMER, SERVING_222, 0x2007U), 0U);
        CHECK(countSent(host, FNE_B, NET_SUBFUNC::ROAM_SERVING_REG_RSP) == 1U);
        const RoamingMessage dereg = lastSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG);
        CHECK(dereg.qualifier == RoamQualifier::ROAMED);
        CHECK(dereg.suid == ROAMER);
        CHECK(host.routes[ROAMER.pack()] == FNE_B);
        CHECK(home.pendingCount() == 1U);

        // the serving side's answer completes the home-originated transaction
        deliver(home, FNE_A, simple(NET_SUBFUNC::ROAM_HOME_DEREG_RSP, ROAMER, dereg.txnId, RoamResult::SUCCESS), 0U);
        CHECK(home.pendingCount() == 0U);
    }

    SECTION("Move_Behind_The_Same_Link_Leaves_The_Home_Deregistration_To_The_Serving_FNE") {
        const RfssIdentity serving13B2 = { 0xDEE00U, 0x13BU, 0x02U };
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2012U), 0U);
        deliver(home, FNE_A, servingReg(ROAMER, serving13B2, 0x2013U), 0U);
        CHECK(countSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP) == 2U);
        CHECK(countSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG) == 0U);
        CHECK(home.pendingCount() == 0U);
        REQUIRE(home.homeRecords().size() == 1U);
        CHECK(home.homeRecords()[0U].serving == serving13B2);
        CHECK(host.routes[ROAMER.pack()] == FNE_A);
    }

    SECTION("Home_Site_Registration_Is_Released_Silently") {
        host.localPeers[0x0F4240U] = HOME_SITE.peerId;
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2008U), 0U);
        CHECK(lastSent(host, HOME_SITE, NET_SUBFUNC::ROAM_HOME_DEREG).qualifier == RoamQualifier::ROAMED);
        REQUIRE(host.removedLocal.size() == 1U);
        CHECK(host.removedLocal[0U] == std::make_pair(HOME_SITE.peerId, 0x0F4240U));
    }

    SECTION("Serving_Deregistration_Only_From_The_Current_Serving_RFSS") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2009U), 0U);
        deliver(home, FNE_A, servingDereg(ROAMER, SERVING_222, 0x200AU), 0U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_DEREG_RSP).result == RoamResult::MME_OBJ_NOT_REG_AT_SERV);
        CHECK(home.homeRecords().size() == 1U);

        deliver(home, FNE_A, servingDereg(ROAMER, SERVING_13B, 0x200BU), 0U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_DEREG_RSP).result == RoamResult::SUCCESS);
        CHECK(home.homeRecords().empty());
        CHECK(host.routes.empty());

        deliver(home, FNE_A, servingDereg(ROAMER, SERVING_13B, 0x200CU), 0U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_DEREG_RSP).result == RoamResult::MME_OBJ_NOT_REG_AT_SERV);
    }

    SECTION("Non_Roamed_Home_Deregistration_On_RID_ACL_Removal") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x200DU), 0U);
        home.revalidateHomeRecords(100U);
        CHECK(countSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG) == 0U);

        host.authorized.clear();
        home.revalidateHomeRecords(200U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG).qualifier == RoamQualifier::NON_ROAMED);
        CHECK(home.homeRecords().empty());
        CHECK(host.routes.empty());
    }

    SECTION("Forced_Query_On_Operator_Request") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x200EU), 0U);
        REQUIRE(home.forcedQuery(ROAMER, 0U));
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_QUERY).queryType == RoamQueryType::FORCED);
        CHECK_FALSE(home.forcedQuery(SUID{ 0xDEE00U, 0x911U, 99U }, 0U));
    }

    SECTION("Records_Expire") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x200FU), 0U);
        home.clock(18000000U - 1U);
        CHECK(home.homeRecords().size() == 1U);
        home.clock(18000000U);
        CHECK(home.homeRecords().empty());
        CHECK(host.routes.empty());
    }

    SECTION("Home_Site_Registration_Deregisters_The_Serving_RFSS") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2010U), 0U);
        home.localRegistration(0x0F4240U, 10U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG).qualifier == RoamQualifier::ROAMED);
        CHECK(home.homeRecords().empty());
        home.localRegistration(0x0F4240U, 20U);
        CHECK(countSent(host, FNE_A, NET_SUBFUNC::ROAM_HOME_DEREG) == 1U);
    }

    SECTION("Not_Confirmed_Presence_From_Another_Serving_RFSS_Must_Be_Confirmed") {
        // a lost Home Deregistration leaves the old serving RFSS refreshing with presence Not Confirmed (BACA 5.5.1(2b))
        deliver(home, FNE_B, servingReg(ROAMER, SERVING_222, 0x2014U), 0U);
        RoamingMessage stale = servingReg(ROAMER, SERVING_13B, 0x2015U);
        stale.presence = RoamPresence::NOT_CONFIRMED;
        deliver(home, FNE_A, stale, 1000U);

        const RoamingMessage rsp = lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP);
        CHECK(rsp.txnId == 0x2015U);
        CHECK(rsp.result == RoamResult::MME_MUST_CONFIRM_SU_PRESENCE);
        CHECK(countSent(host, FNE_B, NET_SUBFUNC::ROAM_HOME_DEREG) == 0U);
        REQUIRE(home.homeRecords().size() == 1U);
        CHECK(home.homeRecords()[0U].serving == SERVING_222);
        CHECK(home.homeRecords()[0U].link == FNE_B);
        CHECK(home.homeRecords()[0U].expiresAtMs == 18000000U);
        CHECK(host.routes[ROAMER.pack()] == FNE_B);

        // a confirmed presence from the same RFSS moves the SU as usual
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2016U), 2000U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP).result == RoamResult::SUCCESS);
        CHECK(countSent(host, FNE_B, NET_SUBFUNC::ROAM_HOME_DEREG) == 1U);
        CHECK(home.homeRecords()[0U].serving == SERVING_13B);
    }

    SECTION("Not_Confirmed_Presence_From_The_Current_Serving_RFSS_Or_Without_A_Record_Is_Accepted") {
        RoamingMessage first = servingReg(ROAMER, SERVING_13B, 0x2017U);
        first.presence = RoamPresence::NOT_CONFIRMED;
        deliver(home, FNE_A, first, 0U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP).result == RoamResult::SUCCESS);

        RoamingMessage refresh = servingReg(ROAMER, SERVING_13B, 0x2018U);
        refresh.presence = RoamPresence::NOT_CONFIRMED;
        deliver(home, FNE_A, refresh, 5000U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP).result == RoamResult::SUCCESS);
        CHECK(home.homeRecords()[0U].expiresAtMs == 5000U + 18000000U);
    }

    SECTION("Serving_Deregistration_Only_From_The_Link_Holding_The_Record") {
        deliver(home, FNE_A, servingReg(ROAMER, SERVING_13B, 0x2019U), 0U);

        // a forged Serving Deregistration naming the right serving RFSS but arriving on another link changes nothing
        deliver(home, FNE_B, servingDereg(ROAMER, SERVING_13B, 0x201AU), 0U);
        CHECK(lastSent(host, FNE_B, NET_SUBFUNC::ROAM_SERVING_DEREG_RSP).result == RoamResult::MME_OBJ_NOT_REG_AT_SERV);
        REQUIRE(home.homeRecords().size() == 1U);
        CHECK(home.homeRecords()[0U].link == FNE_A);
        CHECK(host.routes[ROAMER.pack()] == FNE_A);

        deliver(home, FNE_A, servingDereg(ROAMER, SERVING_13B, 0x201BU), 0U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_DEREG_RSP).result == RoamResult::SUCCESS);
        CHECK(home.homeRecords().empty());
    }

    SECTION("Non_Home_System_Without_A_Route_Is_MME_SU_UNKNOWN") {
        const SUID other = { 0xDEE00U, 0x777U, 5U };
        deliver(home, FNE_A, servingReg(other, SERVING_13B, 0x2011U), 0U);
        CHECK(lastSent(host, FNE_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP).result == RoamResult::MME_SU_UNKNOWN);
    }
}

TEST_CASE("RoamingService forwards Home Deregistration and Query to the serving host", "[fne][roaming][service][serving]")
{
    FakeRoamingHost host;
    RoamingService service(&host);
    service.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    service.linkUp(HOST_LINK, true, false, 0xDEE00U, 0x13BU);
    service.linkUp(FNE_A, true, true, 0xDEE00U, 0x911U);

    deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x3001U), 0U);
    deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x3001U, RoamResult::SUCCESS), 0U);
    REQUIRE(service.servingRecords().size() == 1U);
    host.sent.clear();

    SECTION("Home_Deregistration_Round_Trip") {
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_HOME_DEREG, ROAMER, 0x3002U, RoamQualifier::ROAMED), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == HOST_LINK);
        CHECK(decodeSent(host.sent[0U]).hopCount == 7U);

        deliver(service, HOST_LINK, simple(NET_SUBFUNC::ROAM_HOME_DEREG_RSP, ROAMER, 0x3002U, RoamResult::SUCCESS), 0U);
        REQUIRE(host.sent.size() == 2U);
        CHECK(host.sent[1U].link == FNE_A);
        CHECK(service.servingRecords().empty());
    }

    SECTION("Home_Deregistration_And_Query_From_A_Host_Link_Are_Dropped") {
        // only links facing the home (FNE links) carry Home Deregistration and Query toward a serving host
        const RoamingLink otherHost = { 1002U, false };
        service.linkUp(otherHost, true, false, 0xDEE00U, 0x13BU);
        deliver(service, otherHost, simple(NET_SUBFUNC::ROAM_HOME_DEREG, ROAMER, 0x3005U, RoamQualifier::NON_ROAMED), 0U);
        deliver(service, otherHost, simple(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x3006U, RoamQueryType::FORCED), 0U);
        CHECK(host.sent.empty());
        CHECK(service.pendingCount() == 0U);
        CHECK(service.servingRecords().size() == 1U);
    }

    SECTION("Home_Deregistration_For_An_Unknown_SUID_Is_Not_Found") {
        const SUID unknown = { 0xDEE00U, 0x911U, 99U };
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_HOME_DEREG, unknown, 0x3003U, RoamQualifier::ROAMED), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == FNE_A);
        CHECK(decodeSent(host.sent[0U]).result == RoamResult::MME_SU_UNKNOWN);
    }

    SECTION("Query_Round_Trip") {
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_QUERY, ROAMER, 0x3004U, RoamQueryType::NORMAL_HOME), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == HOST_LINK);

        RoamingMessage qrsp = simple(NET_SUBFUNC::ROAM_QUERY_RSP, ROAMER, 0x3004U, RoamResult::SUCCESS);
        qrsp.interested = 1U;
        deliver(service, HOST_LINK, qrsp, 0U);
        REQUIRE(host.sent.size() == 2U);
        CHECK(host.sent[1U].link == FNE_A);
        CHECK(decodeSent(host.sent[1U]).interested == 1U);
        CHECK(service.servingRecords().size() == 1U);
    }

    SECTION("Serving_Deregistration_From_The_Host_Clears_The_Served_Record") {
        deliver(service, HOST_LINK, servingDereg(ROAMER, SERVING_13B, 0x3005U), 0U);
        REQUIRE(host.sent.size() == 1U);
        CHECK(host.sent[0U].link == FNE_A);
        CHECK(service.servingRecords().empty());
    }
}

TEST_CASE("RoamingService completes a dropped link's transactions as FAILED", "[fne][roaming][service][link]")
{
    FakeRoamingHost host;
    RoamingService service(&host);
    service.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    service.linkUp(HOST_LINK, true, false, 0xDEE00U, 0x13BU);
    service.linkUp(FNE_A, true, true, 0xDEE00U, 0x911U);

    deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x4001U), 0U);
    REQUIRE(service.pendingCount() == 1U);

    SECTION("Link_Drop") {
        service.linkDown(FNE_A);
        CHECK(service.pendingCount() == 0U);
        CHECK_FALSE(service.isLinkCapable(FNE_A));
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x4001U, RoamResult::SUCCESS), 0U);
        CHECK(host.sent.size() == 1U);

        // with the system link gone and no upstream, a new request cannot be routed
        deliver(service, HOST_LINK, servingReg(ROAMER, SERVING_13B, 0x4002U), 0U);
        CHECK(host.sent.size() == 1U);
    }

    SECTION("Pending_Transactions_Expire") {
        service.clock(ROAM_FNE_PENDING_TIMEOUT_MS - 1U);
        CHECK(service.pendingCount() == 1U);
        service.clock(ROAM_FNE_PENDING_TIMEOUT_MS);
        CHECK(service.pendingCount() == 0U);
    }

    SECTION("Host_Link_Drop_Clears_Served_Records") {
        deliver(service, FNE_A, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x4001U, RoamResult::SUCCESS), 0U);
        REQUIRE(service.servingRecords().size() == 1U);
        service.linkDown(HOST_LINK);
        CHECK(service.servingRecords().empty());
    }

    SECTION("Upstream_Default_Is_Dropped_When_The_Link_Reconnects_Without_Roaming") {
        service.linkUp(UPSTREAM, true, true, 0xDEE00U, 0x500U);
        service.linkUp(UPSTREAM, false, true, 0U, 0U);
        const SUID other = { 0xDEE00U, 0x777U, 5U };
        deliver(service, HOST_LINK, servingReg(other, SERVING_13B, 0x4003U), 0U);
        CHECK(host.sent.size() == 1U);
        CHECK(service.pendingCount() == 1U);
    }
}

TEST_CASE("RoamingService serving FNE deregisters a previous serving RFSS behind the same home link", "[fne][roaming][service][chain]")
{
    // home H ($911) reaches serving FNE U ($13B) over one link; U serves hosts A and B, two RFSSs of system $13B
    const RoamingLink H_TO_U = { 2001U, false };
    const RoamingLink U_TO_H = { 3001U, true };
    const RoamingLink HOST_A = { 1001U, false };
    const RoamingLink HOST_B = { 1002U, false };
    const RfssIdentity RFSS_A = { 0xDEE00U, 0x13BU, 0x01U };
    const RfssIdentity RFSS_B = { 0xDEE00U, 0x13BU, 0x02U };

    FakeRoamingHost homeHost;
    RoamingService home(&homeHost);
    home.setIdentity(0xDEE00U, 0x911U, ROAM_DEFAULT_EXPIRES);
    home.linkUp(H_TO_U, true, true, 0xDEE00U, 0x13BU);
    homeHost.authorized.insert(0x0F4240U);

    FakeRoamingHost servingHost;
    RoamingService serving(&servingHost);
    serving.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    serving.linkUp(U_TO_H, true, true, 0xDEE00U, 0x911U);
    serving.linkUp(HOST_A, true, false, 0xDEE00U, 0x13BU);
    serving.linkUp(HOST_B, true, false, 0xDEE00U, 0x13BU);

    // the roamer registers through host A
    deliver(serving, HOST_A, servingReg(ROAMER, RFSS_A, 0x5001U), 0U);
    REQUIRE(pump(servingHost, U_TO_H, home, H_TO_U, 0U) == 1U);
    REQUIRE(pump(homeHost, H_TO_U, serving, U_TO_H, 0U) == 1U);
    REQUIRE(lastSent(servingHost, HOST_A, NET_SUBFUNC::ROAM_SERVING_REG_RSP).result == RoamResult::SUCCESS);
    servingHost.sent.clear();

    // then through host B
    deliver(serving, HOST_B, servingReg(ROAMER, RFSS_B, 0x5002U), 1000U);
    REQUIRE(pump(servingHost, U_TO_H, home, H_TO_U, 1000U) == 1U);

    // the home answers only the success on the shared link, so nothing depends on delivery order
    REQUIRE(homeHost.sent.size() == 1U);
    CHECK(homeHost.sent[0U].subFunc == NET_SUBFUNC::ROAM_SERVING_REG_RSP);
    REQUIRE(pump(homeHost, H_TO_U, serving, U_TO_H, 1000U) == 1U);

    CHECK(lastSent(servingHost, HOST_B, NET_SUBFUNC::ROAM_SERVING_REG_RSP).result == RoamResult::SUCCESS);
    CHECK(countSent(servingHost, HOST_B, NET_SUBFUNC::ROAM_HOME_DEREG) == 0U);
    const RoamingMessage dereg = lastSent(servingHost, HOST_A, NET_SUBFUNC::ROAM_HOME_DEREG);
    CHECK(dereg.qualifier == RoamQualifier::ROAMED);
    CHECK(dereg.suid == ROAMER);
    CHECK(dereg.hopCount == ROAM_DEFAULT_HOP_COUNT);
    REQUIRE(serving.servingRecords().size() == 1U);
    CHECK(serving.servingRecords()[0U].link == HOST_B);
    REQUIRE(home.homeRecords().size() == 1U);
    CHECK(home.homeRecords()[0U].serving == RFSS_B);
    CHECK(home.homeRecords()[0U].link == H_TO_U);
    CHECK(serving.pendingCount() == 1U);

    // host A's answer completes U's own transaction, never reaches the home and leaves B's record in place
    deliver(serving, HOST_A, simple(NET_SUBFUNC::ROAM_HOME_DEREG_RSP, ROAMER, dereg.txnId, RoamResult::SUCCESS), 1100U);
    CHECK(serving.pendingCount() == 0U);
    CHECK(countSent(servingHost, U_TO_H, NET_SUBFUNC::ROAM_HOME_DEREG_RSP) == 0U);
    REQUIRE(serving.servingRecords().size() == 1U);
    CHECK(serving.servingRecords()[0U].link == HOST_B);
}

TEST_CASE("RoamingService home deregisters a previous serving RFSS behind another link in either delivery order", "[fne][roaming][service][chain]")
{
    // home H ($911) reaches serving FNE U1 ($13B, host A) and serving FNE U2 ($222, host B) on separate links
    const RoamingLink H_TO_U1 = { 2001U, false };
    const RoamingLink H_TO_U2 = { 2002U, false };
    const RoamingLink U_TO_H = { 3001U, true };
    const RoamingLink HOST_A = { 1001U, false };
    const RoamingLink HOST_B = { 1002U, false };

    FakeRoamingHost homeHost;
    RoamingService home(&homeHost);
    home.setIdentity(0xDEE00U, 0x911U, ROAM_DEFAULT_EXPIRES);
    home.linkUp(H_TO_U1, true, true, 0xDEE00U, 0x13BU);
    home.linkUp(H_TO_U2, true, true, 0xDEE00U, 0x222U);
    homeHost.authorized.insert(0x0F4240U);

    FakeRoamingHost u1Host;
    RoamingService u1(&u1Host);
    u1.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    u1.linkUp(U_TO_H, true, true, 0xDEE00U, 0x911U);
    u1.linkUp(HOST_A, true, false, 0xDEE00U, 0x13BU);

    FakeRoamingHost u2Host;
    RoamingService u2(&u2Host);
    u2.setIdentity(0xDEE00U, 0x222U, ROAM_DEFAULT_EXPIRES);
    u2.linkUp(U_TO_H, true, true, 0xDEE00U, 0x911U);
    u2.linkUp(HOST_B, true, false, 0xDEE00U, 0x222U);

    deliver(u1, HOST_A, servingReg(ROAMER, SERVING_13B, 0x5101U), 0U);
    REQUIRE(pump(u1Host, U_TO_H, home, H_TO_U1, 0U) == 1U);
    REQUIRE(pump(homeHost, H_TO_U1, u1, U_TO_H, 0U) == 1U);
    REQUIRE(u1.servingRecords().size() == 1U);
    u1Host.sent.clear();

    deliver(u2, HOST_B, servingReg(ROAMER, SERVING_222, 0x5102U), 1000U);
    REQUIRE(pump(u2Host, U_TO_H, home, H_TO_U2, 1000U) == 1U);
    REQUIRE(countSent(homeHost, H_TO_U2, NET_SUBFUNC::ROAM_SERVING_REG_RSP) == 1U);
    REQUIRE(countSent(homeHost, H_TO_U1, NET_SUBFUNC::ROAM_HOME_DEREG) == 1U);

    SECTION("Success_Delivered_First") {
        REQUIRE(pump(homeHost, H_TO_U2, u2, U_TO_H, 1000U) == 1U);
        REQUIRE(pump(homeHost, H_TO_U1, u1, U_TO_H, 1000U) == 1U);
    }

    SECTION("Home_Deregistration_Delivered_First") {
        REQUIRE(pump(homeHost, H_TO_U1, u1, U_TO_H, 1000U) == 1U);
        REQUIRE(pump(homeHost, H_TO_U2, u2, U_TO_H, 1000U) == 1U);
    }

    CHECK(lastSent(u2Host, HOST_B, NET_SUBFUNC::ROAM_SERVING_REG_RSP).result == RoamResult::SUCCESS);
    CHECK(countSent(u2Host, HOST_B, NET_SUBFUNC::ROAM_HOME_DEREG) == 0U);
    REQUIRE(u2.servingRecords().size() == 1U);
    CHECK(u2.servingRecords()[0U].link == HOST_B);
    REQUIRE(home.homeRecords().size() == 1U);
    CHECK(home.homeRecords()[0U].serving == SERVING_222);
    CHECK(home.homeRecords()[0U].link == H_TO_U2);

    // U1 relays the Home Deregistration to host A, and host A's answer back to the home
    const RoamingMessage dereg = lastSent(u1Host, HOST_A, NET_SUBFUNC::ROAM_HOME_DEREG);
    CHECK(dereg.qualifier == RoamQualifier::ROAMED);
    CHECK(dereg.hopCount == 7U);
    deliver(u1, HOST_A, simple(NET_SUBFUNC::ROAM_HOME_DEREG_RSP, ROAMER, dereg.txnId, RoamResult::SUCCESS), 1100U);
    CHECK(u1.servingRecords().empty());
    REQUIRE(pump(u1Host, U_TO_H, home, H_TO_U1, 1100U) == 1U);
    CHECK(home.pendingCount() == 0U);
    CHECK(homeHost.sent.empty());
}

TEST_CASE("RoamingService late Home Deregistration Response does not release a moved roamer", "[fne][roaming][service][chain]")
{
    const RoamingLink HOST_A = { 1001U, false };
    const RoamingLink HOST_B = { 1002U, false };
    const RfssIdentity RFSS_A = { 0xDEE00U, 0x13BU, 0x01U };
    const RfssIdentity RFSS_B = { 0xDEE00U, 0x13BU, 0x02U };

    FakeRoamingHost host;
    RoamingService service(&host);
    service.setIdentity(0xDEE00U, 0x13BU, ROAM_DEFAULT_EXPIRES);
    service.linkUp(UPSTREAM, true, true, 0xDEE00U, 0x911U);
    service.linkUp(HOST_A, true, false, 0xDEE00U, 0x13BU);
    service.linkUp(HOST_B, true, false, 0xDEE00U, 0x13BU);

    deliver(service, HOST_A, servingReg(ROAMER, RFSS_A, 0x6001U), 0U);
    deliver(service, UPSTREAM, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x6001U, RoamResult::SUCCESS), 0U);
    REQUIRE(service.servingRecords().size() == 1U);

    // a home-originated Home Deregistration is relayed toward host A and is still open
    deliver(service, UPSTREAM, simple(NET_SUBFUNC::ROAM_HOME_DEREG, ROAMER, 0x6002U, RoamQualifier::ROAMED), 0U);
    REQUIRE(countSent(host, HOST_A, NET_SUBFUNC::ROAM_HOME_DEREG) == 1U);

    // the roamer moves to host B behind the same home link; U deregisters host A itself
    deliver(service, HOST_B, servingReg(ROAMER, RFSS_B, 0x6003U), 10U);
    deliver(service, UPSTREAM, simple(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ROAMER, 0x6003U, RoamResult::SUCCESS), 10U);
    REQUIRE(countSent(host, HOST_A, NET_SUBFUNC::ROAM_HOME_DEREG) == 2U);
    const RoamingMessage ownDereg = lastSent(host, HOST_A, NET_SUBFUNC::ROAM_HOME_DEREG);
    REQUIRE(service.servingRecords().size() == 1U);
    REQUIRE(service.servingRecords()[0U].link == HOST_B);

    // host A's late answer to the home's request is relayed upstream without releasing B's record
    deliver(service, HOST_A, simple(NET_SUBFUNC::ROAM_HOME_DEREG_RSP, ROAMER, 0x6002U, RoamResult::SUCCESS), 20U);
    CHECK(countSent(host, UPSTREAM, NET_SUBFUNC::ROAM_HOME_DEREG_RSP) == 1U);
    REQUIRE(service.servingRecords().size() == 1U);
    CHECK(service.servingRecords()[0U].link == HOST_B);

    // host A's answer to U's own request is consumed, also without releasing B's record
    deliver(service, HOST_A, simple(NET_SUBFUNC::ROAM_HOME_DEREG_RSP, ROAMER, ownDereg.txnId, RoamResult::SUCCESS), 30U);
    CHECK(countSent(host, UPSTREAM, NET_SUBFUNC::ROAM_HOME_DEREG_RSP) == 1U);
    REQUIRE(service.servingRecords().size() == 1U);
    CHECK(service.servingRecords()[0U].link == HOST_B);
    CHECK(service.pendingCount() == 0U);
}
