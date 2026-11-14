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
#include "host/p25/lookups/P25RoamingClient.h"
#include "common/network/P25Roaming.h"
#include "common/network/RTPFNEHeader.h"

#include <functional>
#include <set>
#include <unordered_map>
#include <vector>

using namespace network;
using namespace network::roaming;
using namespace p25::lookups;

namespace {
    /** @brief Shared harness clock in milliseconds. */
    uint64_t g_now = 0U;

    /** @brief Delivery function for one link direction. */
    typedef std::function<void(uint8_t, const uint8_t*, uint32_t)> Delivery;

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief One FNE: a production RoamingService whose host adapter delivers sends synchronously.
     */
    class HarnessFne : public RoamingServiceHost {
    public:
        /**
         * @brief Initializes a new instance of the HarnessFne class.
         * @param netId System WACN ID.
         * @param sysId System ID.
         */
        HarnessFne(uint32_t netId, uint32_t sysId) :
            service(this),
            authorized(),
            localPeers(),
            removedLocal(),
            links(),
            routes()
        {
            service.setIdentity(netId, sysId, ROAM_DEFAULT_EXPIRES);
        }

        /**
         * @brief Delivers a send to the far end of the link.
         * @param link Link.
         * @param subFunc ROAMING sub-function.
         * @param data Encoded message.
         * @param length Message length.
         * @returns bool True if the link is wired.
         */
        bool sendRoaming(const RoamingLink& link, uint8_t subFunc, const uint8_t* data, uint32_t length) override
        {
            auto it = links.find(link.key());
            if (it == links.end()) {
                return false;
            }

            it->second(subFunc, data, length);
            return true;
        }
        /**
         * @brief Answers from the authorized set (the home RID ACL).
         * @param unitId Unit ID.
         * @returns bool True if authorized.
         */
        bool isHomeUnitAuthorized(uint32_t unitId) override { return authorized.count(unitId) > 0U; }
        /**
         * @brief Answers from the home-site registration map.
         * @param unitId Unit ID.
         * @returns uint32_t Home site peer ID or 0.
         */
        uint32_t findLocalUnitPeer(uint32_t unitId) override
        {
            auto it = localPeers.find(unitId);
            return (it == localPeers.end()) ? 0U : it->second;
        }
        /**
         * @brief Records a home-site registration removal.
         * @param peerId Home site peer ID.
         * @param unitId Unit ID.
         */
        void removeLocalUnitRegistration(uint32_t peerId, uint32_t unitId) override
        {
            removedLocal.push_back(unitId);
            localPeers.erase(unitId);
            (void)peerId;
        }
        /**
         * @brief Records a SUID route.
         * @param suid SUID.
         * @param link Next-hop link.
         */
        void setUnitRoute(const SUID& suid, const RoamingLink& link) override { routes[suid.pack()] = link; }
        /**
         * @brief Removes a SUID route owned by the link.
         * @param suid SUID.
         * @param link Next-hop link.
         */
        void eraseUnitRoute(const SUID& suid, const RoamingLink& link) override
        {
            auto it = routes.find(suid.pack());
            if (it != routes.end() && it->second == link) {
                routes.erase(it);
            }
        }

        RoamingService service;
        std::set<uint32_t> authorized;
        std::unordered_map<uint32_t, uint32_t> localPeers;
        std::vector<uint32_t> removedLocal;
        std::unordered_map<uint64_t, Delivery> links;
        std::unordered_map<uint64_t, RoamingLink> routes;
    };

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief One dvmhost site: a production P25RoamingClient with recording callbacks.
     */
    class HarnessHost {
    public:
        /**
         * @brief Initializes a new instance of the HarnessHost class.
         * @param servingRfss This site's RFSS identity.
         */
        explicit HarnessHost(const RfssIdentity& servingRfss) :
            client(5000U),
            serving(servingRfss),
            capable(true),
            registered(),
            outcomes(),
            homeDeregs(),
            deliver(nullptr)
        {
            client.setContextProvider([this](RfssIdentity& out) {
                out = serving;
                return capable;
            });
            client.setSender([this](uint8_t subFunc, const uint8_t* data, uint32_t length) {
                if (deliver != nullptr) {
                    deliver(subFunc, data, length);
                }
                return true;
            });
            client.setOutcomeCallback([this](const SUID& suid, P25RoamingClient::Outcome outcome, const P25RoamingClient::Profile& profile, bool onAir) {
                (void)profile;
                (void)onAir;
                outcomes.push_back(outcome);
                if (outcome == P25RoamingClient::Outcome::SUCCESS) {
                    registered.insert(suid.pack());
                    return true;
                }
                return false;
            });
            client.setHomeDeregCallback([this](const SUID& suid, uint8_t qualifier) {
                homeDeregs.push_back(qualifier);
                return registered.erase(suid.pack()) > 0U;
            });
            client.setRegCmdCallback([this](const SUID& suid) { return registered.count(suid.pack()) > 0U; });
        }
        HarnessHost(const HarnessHost&) = delete;
        HarnessHost& operator=(const HarnessHost&) = delete;

        P25RoamingClient client;
        RfssIdentity serving;
        bool capable;
        std::set<uint64_t> registered;
        std::vector<P25RoamingClient::Outcome> outcomes;
        std::vector<uint8_t> homeDeregs;
        Delivery deliver;
    };
} // namespace

TEST_CASE("Multi-FNE harness carries Serving Registration, refresh, Home Deregistration and Serving Deregistration",
    "[fne][roaming][harness]")
{
    g_now = 0U;

    HarnessFne fneA(0xDEE00U, 0x13BU);                                              // serving system $13B
    HarnessFne fneB(0xDEE00U, 0x911U);                                              // home system $911
    HarnessFne fneC(0xDEE00U, 0x222U);                                              // second serving system $222
    fneB.authorized.insert(0x0F4240U);

    // A sees B as downstream FNE peer 2001; B reaches A through its upstream link (own peer ID 2001); B-C likewise
    const RoamingLink aToB = { 2001U, false };
    const RoamingLink bToA = { 2001U, true };
    const RoamingLink bToC = { 2002U, false };
    const RoamingLink cToB = { 2002U, true };
    const RoamingLink aHost = { 1001U, false };
    const RoamingLink cHost = { 3001U, false };

    fneA.service.linkUp(aHost, true, false, 0xDEE00U, 0x13BU);
    fneA.service.linkUp(aToB, true, true, 0xDEE00U, 0x911U);
    fneB.service.linkUp(bToA, true, true, 0xDEE00U, 0x13BU);
    fneB.service.linkUp(bToC, true, true, 0xDEE00U, 0x222U);
    fneC.service.linkUp(cToB, true, true, 0xDEE00U, 0x911U);
    fneC.service.linkUp(cHost, true, false, 0xDEE00U, 0x222U);

    HarnessHost hostA(RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U });
    HarnessHost hostC(RfssIdentity{ 0xDEE00U, 0x222U, 0x01U });

    fneA.links[aToB.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneB.service.process(bToA, s, d, l, g_now); };
    fneB.links[bToA.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneA.service.process(aToB, s, d, l, g_now); };
    fneB.links[bToC.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneC.service.process(cToB, s, d, l, g_now); };
    fneC.links[cToB.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneB.service.process(bToC, s, d, l, g_now); };
    fneA.links[aHost.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { hostA.client.processMessage(s, d, l); };
    fneC.links[cHost.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { hostC.client.processMessage(s, d, l); };
    hostA.deliver = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneA.service.process(aHost, s, d, l, g_now); };
    hostC.deliver = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneC.service.process(cHost, s, d, l, g_now); };

    const SUID roamer = { 0xDEE00U, 0x911U, 0x0F4240U };

    // cross-system Serving Registration: host on $13B -> FNE A -> FNE B (home) -> FNE A -> host (spec 4.1)
    REQUIRE(hostA.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    REQUIRE(hostA.outcomes.size() == 1U);
    CHECK(hostA.outcomes[0U] == P25RoamingClient::Outcome::SUCCESS);
    CHECK(hostA.client.isRoamer(roamer));
    REQUIRE(fneB.service.homeRecords().size() == 1U);
    CHECK(fneB.service.homeRecords()[0U].serving == RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U });
    CHECK(fneB.service.homeRecords()[0U].link == bToA);
    REQUIRE(fneA.service.servingRecords().size() == 1U);
    CHECK(fneA.service.servingRecords()[0U].link == aHost);
    REQUIRE(fneB.routes.count(roamer.pack()) == 1U);
    CHECK(fneB.routes[roamer.pack()] == bToA);
    CHECK(fneA.service.pendingCount() == 0U);
    CHECK(fneB.service.pendingCount() == 0U);

    // refresh at 80 % of expires renews the home record (spec 4.2)
    g_now = 14400000U;
    hostA.client.clock(14400000U);
    REQUIRE(hostA.outcomes.size() == 2U);
    CHECK(hostA.outcomes[1U] == P25RoamingClient::Outcome::SUCCESS);
    REQUIRE(fneB.service.homeRecords().size() == 1U);
    CHECK(fneB.service.homeRecords()[0U].expiresAtMs == 14400000U + 18000000U);

    // the SU moves to $222 behind FNE C: the home deregisters the old serving RFSS (Roamed, spec 4.1 step 5.3)
    REQUIRE(hostC.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    CHECK(hostC.client.isRoamer(roamer));
    REQUIRE(fneB.service.homeRecords().size() == 1U);
    CHECK(fneB.service.homeRecords()[0U].serving == RfssIdentity{ 0xDEE00U, 0x222U, 0x01U });
    REQUIRE(hostA.homeDeregs.size() == 1U);
    CHECK(hostA.homeDeregs[0U] == RoamQualifier::ROAMED);
    CHECK_FALSE(hostA.client.isRoamer(roamer));
    CHECK(fneA.service.servingRecords().empty());
    CHECK(fneB.service.pendingCount() == 0U);
    CHECK(fneB.routes[roamer.pack()] == bToC);

    // Serving Deregistration from the new serving host clears the home record and route (spec 4.3)
    CHECK(hostC.client.servingDeregistration(roamer));
    CHECK(fneB.service.homeRecords().empty());
    CHECK(fneC.service.servingRecords().empty());
    CHECK(fneB.routes.count(roamer.pack()) == 0U);
    CHECK(fneC.service.pendingCount() == 0U);

    // the SU registers at A again, then on one of the home's own sites: the home deregisters A (Roamed)
    REQUIRE(hostA.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    REQUIRE(hostA.client.isRoamer(roamer));
    fneB.service.localRegistration(0x0F4240U, g_now);
    REQUIRE(hostA.homeDeregs.size() == 2U);
    CHECK(hostA.homeDeregs[1U] == RoamQualifier::ROAMED);
    CHECK_FALSE(hostA.client.isRoamer(roamer));
    CHECK(fneB.service.homeRecords().empty());
}

TEST_CASE("Multi-FNE harness denies an unknown home unit and fails a request whose link drops while pending", "[fne][roaming][harness]")
{
    g_now = 0U;

    HarnessFne fneA(0xDEE00U, 0x13BU);
    HarnessFne fneB(0xDEE00U, 0x911U);
    const RoamingLink aToB = { 2001U, false };
    const RoamingLink bToA = { 2001U, true };
    const RoamingLink aHost = { 1001U, false };
    fneA.service.linkUp(aHost, true, false, 0xDEE00U, 0x13BU);
    fneA.service.linkUp(aToB, true, true, 0xDEE00U, 0x911U);
    fneB.service.linkUp(bToA, true, true, 0xDEE00U, 0x13BU);

    HarnessHost hostA(RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U });
    fneA.links[aToB.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneB.service.process(bToA, s, d, l, g_now); };
    fneB.links[bToA.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneA.service.process(aToB, s, d, l, g_now); };
    fneA.links[aHost.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { hostA.client.processMessage(s, d, l); };
    hostA.deliver = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneA.service.process(aHost, s, d, l, g_now); };

    // the home RID ACL does not hold the unit: MME_SU_UNKNOWN reaches the host as REJECTED (REG_DENY on air)
    const SUID unknown = { 0xDEE00U, 0x911U, 99U };
    REQUIRE(hostA.client.requestRegistration(unknown, true) == P25RoamingClient::RequestResult::SENT);
    REQUIRE(hostA.outcomes.size() == 1U);
    CHECK(hostA.outcomes[0U] == P25RoamingClient::Outcome::REJECTED);
    CHECK(fneB.service.homeRecords().empty());

    // the forwarded Serving Registration is parked on the A-to-B link (never reaches the home) so it stays pending at A
    uint32_t parked = 0U;
    fneA.links[aToB.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) {
        (void)s;
        (void)d;
        (void)l;
        parked++;
    };
    const SUID roamer = { 0xDEE00U, 0x911U, 0x0F4240U };
    fneB.authorized.insert(0x0F4240U);
    REQUIRE(hostA.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    CHECK(parked == 1U);
    CHECK(fneA.service.pendingCount() == 1U);
    CHECK(hostA.outcomes.size() == 1U);

    // dropping the link completes the pending transaction at FNE A (spec 6); FAILED is a local outcome that is never
    // encoded, so FNE A sends nothing and the host is still waiting
    fneA.service.linkDown(aToB);
    CHECK(fneA.service.pendingCount() == 0U);
    CHECK(parked == 1U);
    CHECK(hostA.outcomes.size() == 1U);
    CHECK(hostA.client.isPending(roamer));

    // the host reaches FAILED only through its own roamingHomeTimeout (5000 ms here)
    hostA.client.clock(4999U);
    CHECK(hostA.outcomes.size() == 1U);
    hostA.client.clock(1U);
    REQUIRE(hostA.outcomes.size() == 2U);
    CHECK(hostA.outcomes[1U] == P25RoamingClient::Outcome::FAILED);
    CHECK_FALSE(hostA.client.isPending(roamer));
    CHECK(hostA.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::HELD_OFF);
}

TEST_CASE("Multi-FNE harness moves a roamer between two serving RFSSs behind one FNE link", "[fne][roaming][harness]")
{
    g_now = 0U;

    HarnessFne fneA(0xDEE00U, 0x13BU);
    HarnessFne fneB(0xDEE00U, 0x911U);
    fneB.authorized.insert(0x0F4240U);

    const RoamingLink aToB = { 2001U, false };
    const RoamingLink bToA = { 2001U, true };
    const RoamingLink aHost1 = { 1001U, false };
    const RoamingLink aHost2 = { 1002U, false };
    fneA.service.linkUp(aHost1, true, false, 0xDEE00U, 0x13BU);
    fneA.service.linkUp(aHost2, true, false, 0xDEE00U, 0x13BU);
    fneA.service.linkUp(aToB, true, true, 0xDEE00U, 0x911U);
    fneB.service.linkUp(bToA, true, true, 0xDEE00U, 0x13BU);

    // two sites of serving system $13B (RFSS 1 and RFSS 2) behind the same FNE A
    HarnessHost host1(RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U });
    HarnessHost host2(RfssIdentity{ 0xDEE00U, 0x13BU, 0x02U });
    fneA.links[aToB.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneB.service.process(bToA, s, d, l, g_now); };
    // count the Home Deregistrations that cross the home-to-A link and the A-to-host-1 link so the sender is proven
    uint32_t homeDeregsBToA = 0U;
    uint32_t homeDeregsAToHost1 = 0U;
    fneB.links[bToA.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) {
        if (s == NET_SUBFUNC::ROAM_HOME_DEREG) {
            homeDeregsBToA++;
        }
        fneA.service.process(aToB, s, d, l, g_now);
    };
    fneA.links[aHost1.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) {
        if (s == NET_SUBFUNC::ROAM_HOME_DEREG) {
            homeDeregsAToHost1++;
        }
        host1.client.processMessage(s, d, l);
    };
    fneA.links[aHost2.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { host2.client.processMessage(s, d, l); };
    host1.deliver = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneA.service.process(aHost1, s, d, l, g_now); };
    host2.deliver = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneA.service.process(aHost2, s, d, l, g_now); };

    const SUID roamer = { 0xDEE00U, 0x911U, 0x0F4240U };

    REQUIRE(host1.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    REQUIRE(host1.client.isRoamer(roamer));
    REQUIRE(fneA.service.servingRecords().size() == 1U);
    CHECK(fneA.service.servingRecords()[0U].link == aHost1);

    // both RFSSs are behind link bToA, so the home sends no Home Deregistration: the relaying serving FNE (A) sees
    // its served-roamer record change link and deregisters the old RFSS (Roamed, BACA 5.1)
    REQUIRE(host2.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    CHECK(host2.client.isRoamer(roamer));
    REQUIRE(host1.homeDeregs.size() == 1U);
    CHECK(host1.homeDeregs[0U] == RoamQualifier::ROAMED);
    CHECK_FALSE(host1.client.isRoamer(roamer));
    CHECK(host2.homeDeregs.empty());
    CHECK(homeDeregsBToA == 0U);
    CHECK(homeDeregsAToHost1 == 1U);
    REQUIRE(fneA.service.servingRecords().size() == 1U);
    CHECK(fneA.service.servingRecords()[0U].link == aHost2);
    REQUIRE(fneB.service.homeRecords().size() == 1U);
    CHECK(fneB.service.homeRecords()[0U].serving == RfssIdentity{ 0xDEE00U, 0x13BU, 0x02U });
    CHECK(fneB.service.homeRecords()[0U].link == bToA);
    CHECK(fneA.service.pendingCount() == 0U);
    CHECK(fneB.service.pendingCount() == 0U);
}

TEST_CASE("Multi-FNE harness keeps a moved roamer when the old serving RFSS missed its Home Deregistration", "[fne][roaming][harness]")
{
    g_now = 0U;

    HarnessFne fneA(0xDEE00U, 0x13BU);                                              // serving system $13B
    HarnessFne fneB(0xDEE00U, 0x911U);                                              // home system $911
    HarnessFne fneC(0xDEE00U, 0x222U);                                              // second serving system $222
    fneB.authorized.insert(0x0F4240U);

    const RoamingLink aToB = { 2001U, false };
    const RoamingLink bToA = { 2001U, true };
    const RoamingLink bToC = { 2002U, false };
    const RoamingLink cToB = { 2002U, true };
    const RoamingLink aHost = { 1001U, false };
    const RoamingLink cHost = { 3001U, false };

    fneA.service.linkUp(aHost, true, false, 0xDEE00U, 0x13BU);
    fneA.service.linkUp(aToB, true, true, 0xDEE00U, 0x911U);
    fneB.service.linkUp(bToA, true, true, 0xDEE00U, 0x13BU);
    fneB.service.linkUp(bToC, true, true, 0xDEE00U, 0x222U);
    fneC.service.linkUp(cToB, true, true, 0xDEE00U, 0x911U);
    fneC.service.linkUp(cHost, true, false, 0xDEE00U, 0x222U);

    HarnessHost hostA(RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U });
    HarnessHost hostC(RfssIdentity{ 0xDEE00U, 0x222U, 0x01U });

    // the home-to-A link loses every Home Deregistration
    uint32_t lostHomeDeregs = 0U;
    fneA.links[aToB.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneB.service.process(bToA, s, d, l, g_now); };
    fneB.links[bToA.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) {
        if (s == NET_SUBFUNC::ROAM_HOME_DEREG) {
            lostHomeDeregs++;
            return;
        }
        fneA.service.process(aToB, s, d, l, g_now);
    };
    fneB.links[bToC.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneC.service.process(cToB, s, d, l, g_now); };
    fneC.links[cToB.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneB.service.process(bToC, s, d, l, g_now); };
    fneA.links[aHost.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { hostA.client.processMessage(s, d, l); };
    fneC.links[cHost.key()] = [&](uint8_t s, const uint8_t* d, uint32_t l) { hostC.client.processMessage(s, d, l); };
    hostA.deliver = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneA.service.process(aHost, s, d, l, g_now); };
    hostC.deliver = [&](uint8_t s, const uint8_t* d, uint32_t l) { fneC.service.process(cHost, s, d, l, g_now); };

    const SUID roamer = { 0xDEE00U, 0x911U, 0x0F4240U };
    REQUIRE(hostA.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    REQUIRE(hostA.client.isRoamer(roamer));

    // the SU moves to $222; the Roamed Home Deregistration toward A is lost, so host A still holds the SU
    g_now = 1000U;
    REQUIRE(hostC.client.requestRegistration(roamer, true) == P25RoamingClient::RequestResult::SENT);
    REQUIRE(hostC.client.isRoamer(roamer));
    CHECK(lostHomeDeregs == 1U);
    REQUIRE(hostA.client.isRoamer(roamer));

    // host A's timer refresh (presence Not Confirmed) must not take the SU back: the home answers
    //  MME_MUST_CONFIRM_SU_PRESENCE and host A releases the roamer silently (spec 4.2)
    g_now = 14400000U;
    hostA.client.clock(14400000U);
    REQUIRE(hostA.outcomes.size() == 2U);
    CHECK(hostA.outcomes[1U] == P25RoamingClient::Outcome::REJECTED);
    CHECK_FALSE(hostA.client.isRoamer(roamer));
    CHECK(hostC.client.isRoamer(roamer));
    CHECK(hostC.homeDeregs.empty());
    REQUIRE(fneB.service.homeRecords().size() == 1U);
    CHECK(fneB.service.homeRecords()[0U].serving == RfssIdentity{ 0xDEE00U, 0x222U, 0x01U });
    CHECK(fneB.service.homeRecords()[0U].link == bToC);
    CHECK(fneB.routes[roamer.pack()] == bToC);
    CHECK(fneA.service.pendingCount() == 0U);
    CHECK(fneB.service.pendingCount() == 1U);                                       // the lost Home Deregistration
}
