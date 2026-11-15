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

#include "fne/FNETestHooks.h"
#include "fne/HostFNE.h"
#include "fne/network/RoamingConfig.h"
#include "common/BitManipulation.h"
#include "common/lookups/PeerListLookup.h"
#include "common/lookups/RadioIdLookup.h"
#include "common/lookups/TalkgroupRulesLookup.h"
#include "common/network/P25Roaming.h"
#include "common/yaml/Yaml.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

using namespace network;
using namespace network::roaming;

namespace {
    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Socket-free FNE harness for roaming tests (the traffic network is never opened).
     */
    class RoamingFNEHarness {
    public:
        /**
         * @brief Initializes a new instance of the RoamingFNEHarness class.
         */
        RoamingFNEHarness() :
            configFile("fne-test.yml"),
            host(configFile),
            radios("", 0U, true, false),
            talkgroups("", 0U, true, false),
            peers("", 0U, true, false),
            traffic(&host, "127.0.0.1", 62041U, 999999U, "test-password", "test-fne",
                false, false, false, false, true, true, true, true, true,
                0U, false, true, true, true, 5U, 10U, 2U),
            metadata(&host, &traffic, "127.0.0.1", 62042U, 2U)
        {
            traffic.setLookups(&radios, nullptr, &talkgroups, &peers, nullptr, nullptr);
        }
        /**
         * @brief Finalizes a instance of the RoamingFNEHarness class.
         */
        ~RoamingFNEHarness()
        {
            FNETestHooks::clearPeerWriteCapture(traffic);
            FNETestHooks::clearMetadataWriteCapture(metadata);
            FNETestHooks::clearPeers(traffic);
        }

        std::string configFile;
        HostFNE host;
        lookups::RadioIdLookup radios;
        lookups::TalkgroupRulesLookup talkgroups;
        lookups::PeerListLookup peers;
        network::TrafficNetwork traffic;
        network::MetadataNetwork metadata;
    };

    // ---------------------------------------------------------------------------
    //  Global Functions
    // ---------------------------------------------------------------------------

    /**
     * @brief Builds an enabled roaming configuration.
     * @param netId System WACN ID.
     * @param sysId System ID.
     * @returns RoamingConfig Enabled configuration with the default expires.
     */
    RoamingConfig configFor(uint32_t netId, uint32_t sysId)
    {
        RoamingConfig config;
        REQUIRE(config.set(netId, sysId, ROAM_DEFAULT_EXPIRES));
        return config;
    }

    /**
     * @brief Loads a roaming configuration from a YAML document holding system keys.
     * @param document YAML text.
     * @param[out] config Configuration to load.
     * @returns RoamingConfigLoad::E Load result.
     */
    RoamingConfigLoad::E loadFrom(const std::string& document, RoamingConfig& config)
    {
        yaml::Node root;
        REQUIRE(yaml::Parse(root, document));
        return config.load(root);
    }

    /**
     * @brief Parses a JSON object literal.
     * @param text JSON text.
     * @returns json::object Parsed object.
     */
    json::object parseObject(const std::string& text)
    {
        json::value v;
        REQUIRE(json::parse(v, text).empty());
        REQUIRE(v.is<json::object>());
        return v.get<json::object>();
    }

    /**
     * @brief Builds an RPTC packet (8-byte header, then JSON) as FNETestHooks::dispatchTraffic delivers it.
     * @param json Configuration JSON text.
     * @returns std::vector<uint8_t> Packet bytes.
     */
    std::vector<uint8_t> rptcPacket(const std::string& json)
    {
        std::vector<uint8_t> packet(8U, 0x00U);
        ::memcpy(packet.data(), "RPTC", 4U);
        packet.insert(packet.end(), json.begin(), json.end());
        return packet;
    }
} // namespace

TEST_CASE("FNE P25 roaming configuration loads and validates the system identity", "[fne][roaming][config]")
{
    RoamingConfig config;

    CHECK(loadFrom("identity: MASTERFNE\n", config) == RoamingConfigLoad::OK);
    CHECK_FALSE(config.enabled());
    CHECK(config.expires() == ROAM_DEFAULT_EXPIRES);

    CHECK(loadFrom("p25NetId: 0\np25SysId: 0\n", config) == RoamingConfigLoad::OK);
    CHECK_FALSE(config.enabled());

    REQUIRE(loadFrom("p25NetId: DEE00\np25SysId: 13B\n", config) == RoamingConfigLoad::OK);
    CHECK(config.enabled());
    CHECK(config.netId() == 0xDEE00U);
    CHECK(config.sysId() == 0x13BU);
    CHECK(config.expires() == 18000U);

    REQUIRE(loadFrom("p25NetId: 0xDEE00\np25SysId: 0x911\np25RoamingExpires: 14401\n", config) == RoamingConfigLoad::OK);
    CHECK(config.enabled());
    CHECK(config.sysId() == 0x911U);
    CHECK(config.expires() == 14401U);

    CHECK(loadFrom("p25NetId: DEE00\np25SysId: 13B\np25RoamingExpires: 14400\n", config) == RoamingConfigLoad::EXPIRES_TOO_SHORT);
    CHECK_FALSE(config.enabled());

    // the BEE00 - BEEFF range is never accepted (AGENTS.md P25 WACN protection)
    CHECK(loadFrom("p25NetId: BEE00\np25SysId: 13B\n", config) == RoamingConfigLoad::PROTECTED_WACN);
    CHECK(loadFrom("p25NetId: BEE10\np25SysId: 13B\n", config) == RoamingConfigLoad::PROTECTED_WACN);
    CHECK(loadFrom("p25NetId: BEEFF\np25SysId: 13B\n", config) == RoamingConfigLoad::PROTECTED_WACN);
    CHECK_FALSE(config.enabled());
    // the protected range fails startup whatever p25SysId holds
    CHECK(loadFrom("p25NetId: BEE00\n", config) == RoamingConfigLoad::PROTECTED_WACN);
    CHECK(loadFrom("p25NetId: BEE00\np25SysId: 0\n", config) == RoamingConfigLoad::PROTECTED_WACN);
    CHECK(loadFrom("p25NetId: BEEFF\np25SysId: XYZ\n", config) == RoamingConfigLoad::PROTECTED_WACN);
    CHECK(loadFrom("p25NetId: BEE80\np25SysId: 1000\np25RoamingExpires: 100\n", config) == RoamingConfigLoad::PROTECTED_WACN);
    CHECK_FALSE(config.enabled());
    CHECK(loadFrom("p25NetId: BEDFF\np25SysId: 13B\n", config) == RoamingConfigLoad::OK);
    CHECK(loadFrom("p25NetId: BEF00\np25SysId: 13B\n", config) == RoamingConfigLoad::OK);

    CHECK(loadFrom("p25NetId: DEE00\n", config) == RoamingConfigLoad::INVALID);
    CHECK(loadFrom("p25NetId: DEE00\np25SysId: 0\n", config) == RoamingConfigLoad::INVALID);
    CHECK(loadFrom("p25NetId: XYZ\np25SysId: 13B\n", config) == RoamingConfigLoad::INVALID);
    CHECK(loadFrom("p25NetId: 100000\np25SysId: 13B\n", config) == RoamingConfigLoad::INVALID);
    CHECK(loadFrom("p25NetId: DEE00\np25SysId: 1000\n", config) == RoamingConfigLoad::INVALID);
    CHECK_FALSE(config.enabled());

    uint32_t value = 0U;
    CHECK(RoamingConfig::parseHex("FFFFF", ROAM_MAX_WACN, value));
    CHECK(value == 0xFFFFFU);
    CHECK_FALSE(RoamingConfig::parseHex("", ROAM_MAX_WACN, value));
    CHECK_FALSE(RoamingConfig::parseHex("0x", ROAM_MAX_WACN, value));
    CHECK_FALSE(RoamingConfig::parseHex("-1", ROAM_MAX_WACN, value));
    CHECK_FALSE(RoamingConfig::parseHex("12 3", ROAM_MAX_WACN, value));
    CHECK_FALSE(RoamingConfig::parseHex("123456789", 0xFFFFFFFFU, value));
}

TEST_CASE("FNE P25 roaming login evaluation and configuration ACK", "[fne][roaming][login]")
{
    const RoamingConfig config = configFor(0xDEE00U, 0x13BU);
    RoamingPeerConfig peer;

    // spec 3.1 example: WACN 912896 ($DEE00), System 315 ($13B)
    CHECK(config.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 1}}"),
        false, peer) == RoamingLogin::CAPABLE);
    CHECK(peer.rfssId == 1U);

    CHECK(config.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 2321, \"rfssId\": 1}}"),
        false, peer) == RoamingLogin::REJECT_MISMATCH);
    CHECK(peer.sysId == 0x911U);

    CHECK(config.evaluateLogin(parseObject("{\"identity\": \"old host\"}"), false, peer) == RoamingLogin::NOT_CAPABLE);
    CHECK(config.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 2, \"netId\": 912896, \"sysId\": 2321}}"), false, peer) ==
        RoamingLogin::NOT_CAPABLE);

    // a downstream FNE is another system and may carry any identity
    CHECK(config.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 2321, \"rfssId\": 0}}"),
        true, peer) == RoamingLogin::CAPABLE);
    CHECK(peer.sysId == 0x911U);

    // a downstream FNE offering this system's own identity would be a second home (one FNE per system holds it)
    CHECK(config.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 0}}"),
        true, peer) == RoamingLogin::SAME_SYSTEM_FNE);
    CHECK(peer.sysId == 0x13BU);

    // a protected BEE00 - BEEFF WACN is refused from any peer
    CHECK(config.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 1, \"netId\": 781824, \"sysId\": 2321, \"rfssId\": 0}}"),
        true, peer) == RoamingLogin::REJECT_PROTECTED_WACN);
    CHECK(config.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 1, \"netId\": 782079, \"sysId\": 315, \"rfssId\": 1}}"),
        false, peer) == RoamingLogin::REJECT_PROTECTED_WACN);

    // an FNE without an identity never negotiates and never rejects
    RoamingConfig disabled;
    CHECK(disabled.evaluateLogin(parseObject("{\"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 2321, \"rfssId\": 1}}"),
        false, peer) == RoamingLogin::NOT_CAPABLE);

    uint8_t payload[CONFIG_ACK_ROAMING_LEN];
    REQUIRE(config.buildConfigAck(payload, sizeof(payload)) == 6U);
    CHECK(std::vector<uint8_t>(payload, payload + 6U) == std::vector<uint8_t>({ 0xC0U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU }));
    REQUIRE(disabled.buildConfigAck(payload, sizeof(payload)) == 1U);
    CHECK(payload[0U] == 0x80U);
}

TEST_CASE("FNE rejects a host whose P25 identity differs from the system identity", "[fne][roaming][login]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
    REQUIRE(harness.traffic.p25RoamingConfig().enabled());

    FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
        rptcPacket("{\"identity\": \"SITE911\", \"peerClass\": 0, \"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 2321, \"rfssId\": 1}}"));

    CHECK_FALSE(FNETestHooks::hasPeer(harness.traffic, 1001U));
}

TEST_CASE("FNE accepts hosts that offer a matching identity or no P25 roaming object", "[fne][roaming][login]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));

    // a host offering the system identity negotiates roaming
    network::FNEPeerConnection& capable = FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
        rptcPacket("{\"identity\": \"SITE315\", \"peerClass\": 0, \"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 2}}"));
    REQUIRE(FNETestHooks::hasPeer(harness.traffic, 1001U));
    CHECK(FNETestHooks::peerState(harness.traffic, 1001U) == network::NET_STAT_RUNNING);
    CHECK(capable.p25RoamingCapable());
    CHECK(capable.p25NetId() == 0xDEE00U);
    CHECK(capable.p25SysId() == 0x13BU);
    CHECK(capable.p25RfssId() == 2U);

    // a host without the object (conventional, older host) is accepted exactly as before
    network::FNEPeerConnection& legacy = FNETestHooks::addPeer(harness.traffic, 1002U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1002U,
        rptcPacket("{\"identity\": \"SITE316\", \"peerClass\": 0}"));
    REQUIRE(FNETestHooks::hasPeer(harness.traffic, 1002U));
    CHECK(FNETestHooks::peerState(harness.traffic, 1002U) == network::NET_STAT_RUNNING);
    CHECK_FALSE(legacy.p25RoamingCapable());
    CHECK(legacy.p25NetId() == 0U);
    CHECK(legacy.p25SysId() == 0U);
}

TEST_CASE("FNE without a P25 identity accepts any host identity as not roaming capable", "[fne][roaming][login]")
{
    RoamingFNEHarness harness;
    REQUIRE_FALSE(harness.traffic.p25RoamingConfig().enabled());

    network::FNEPeerConnection& host = FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
        rptcPacket("{\"identity\": \"SITE911\", \"peerClass\": 0, \"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 2321, \"rfssId\": 1}}"));
    REQUIRE(FNETestHooks::hasPeer(harness.traffic, 1001U));
    CHECK(FNETestHooks::peerState(harness.traffic, 1001U) == network::NET_STAT_RUNNING);
    CHECK_FALSE(host.p25RoamingCapable());
}

TEST_CASE("FNE decides the neighbor exemption with the same precedence as the peer class", "[fne][roaming][login]")
{
    const std::string foreign = "\"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 2321, \"rfssId\": 1}";

    // peerClass overrides externalPeer: a standard host claiming externalPeer is still checked and rejected
    {
        RoamingFNEHarness harness;
        harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
        FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
        FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
            rptcPacket("{\"identity\": \"SITE911\", \"externalPeer\": true, \"peerClass\": 0, " + foreign + "}"));
        CHECK_FALSE(FNETestHooks::hasPeer(harness.traffic, 1001U));
    }
    {
        RoamingFNEHarness harness;
        harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
        FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
        FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
            rptcPacket("{\"identity\": \"SITE911\", \"externalPeer\": true, \"peerClass\": 2, " + foreign + "}"));
        CHECK_FALSE(FNETestHooks::hasPeer(harness.traffic, 1001U));
    }

    // a downstream FNE (externalPeer, or peerClass neighbor) may carry any identity
    {
        RoamingFNEHarness harness;
        harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
        network::FNEPeerConnection& neighbor = FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
        FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
            rptcPacket("{\"identity\": \"FNE911\", \"externalPeer\": true, " + foreign + "}"));
        REQUIRE(FNETestHooks::hasPeer(harness.traffic, 1001U));
        CHECK(neighbor.peerClass() == network::PEER_CONN_CLASS_NEIGHBOR);
        CHECK(neighbor.p25RoamingCapable());
        CHECK(neighbor.p25SysId() == 0x911U);
    }
    {
        RoamingFNEHarness harness;
        harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
        network::FNEPeerConnection& neighbor = FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
        FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
            rptcPacket("{\"identity\": \"FNE911\", \"peerClass\": 1, " + foreign + "}"));
        REQUIRE(FNETestHooks::hasPeer(harness.traffic, 1001U));
        CHECK(neighbor.peerClass() == network::PEER_CONN_CLASS_NEIGHBOR);
        CHECK(neighbor.p25RoamingCapable());
    }
}

namespace {
    /**
     * @brief Builds a 24-byte GRANT_REQ payload (layout in BaseNetwork.h writeGrantReq).
     * @param srcId Source unit ID.
     * @param dstId Destination unit ID.
     * @param netId Source WACN ID (0 = own system).
     * @param sysId Source System ID (0 = own system).
     * @returns std::vector<uint8_t> Payload bytes.
     */
    std::vector<uint8_t> grantRequest(uint32_t srcId, uint32_t dstId, uint32_t netId, uint32_t sysId)
    {
        const uint8_t P25_MODE = 2U;                                                // DVM_STATE::STATE_P25 (src/host/modem/Modem.h:120)
        std::vector<uint8_t> packet(ROAM_GRANT_REQ_LEN, 0x00U);
        SET_UINT24(netId, packet.data(), 4U);
        SET_UINT16(sysId, packet.data(), 7U);
        SET_UINT24(srcId, packet.data(), 11U);
        SET_UINT24(dstId, packet.data(), 15U);
        packet[19U] = 0x80U;                                                        // unit-to-unit
        packet[20U] = P25_MODE;
        packet[21U] = 0x04U;                                                        // service options
        return packet;
    }
} // namespace

TEST_CASE("FNE grant requests honor the source system fields", "[fne][roaming][grant]")
{
    constexpr uint32_t SOURCE_PEER = 1001U;
    constexpr uint32_t TARGET_PEER = 1002U;
    constexpr uint32_t SOURCE_ID = 2001U;
    constexpr uint32_t DESTINATION_ID = 2002U;

    auto run = [&](const std::vector<uint8_t>& packet) {
        RoamingFNEHarness harness;
        harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
        FNETestHooks::addPeer(harness.traffic, SOURCE_PEER, network::NET_STAT_RUNNING, true);
        FNETestHooks::addPeer(harness.traffic, TARGET_PEER, network::NET_STAT_RUNNING, true);
        harness.radios.addEntry(SOURCE_ID, true, "test source");
        harness.radios.addEntry(DESTINATION_ID, true, "test destination");
        FNETestHooks::registerP25Unit(harness.traffic, TARGET_PEER, DESTINATION_ID);

        std::vector<uint32_t> writes;
        FNETestHooks::capturePeerWrites(harness.traffic, writes);
        FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::GRANT_REQ, network::NET_SUBFUNC::NOP, SOURCE_PEER, packet);
        std::sort(writes.begin(), writes.end());
        return writes;
    };

    // zero (older hosts) and this system's own identity are processed exactly as before
    CHECK(run(grantRequest(SOURCE_ID, DESTINATION_ID, 0U, 0U)) == std::vector<uint32_t>({ SOURCE_PEER, TARGET_PEER }));
    CHECK(run(grantRequest(SOURCE_ID, DESTINATION_ID, 0xDEE00U, 0x13BU)) == std::vector<uint32_t>({ SOURCE_PEER, TARGET_PEER }));

    // a cross-system source is not served until group/unit-to-unit mobility (3c/3d)
    CHECK(run(grantRequest(SOURCE_ID, DESTINATION_ID, 0xDEE00U, 0x911U)).empty());

    // out-of-range System ID and a truncated request are dropped
    std::vector<uint8_t> badSys = grantRequest(SOURCE_ID, DESTINATION_ID, 0U, 0U);
    badSys[7U] = 0x10U;
    CHECK(run(badSys).empty());
    std::vector<uint8_t> truncated = grantRequest(SOURCE_ID, DESTINATION_ID, 0U, 0U);
    truncated.resize(ROAM_GRANT_REQ_LEN - 1U);
    CHECK(run(truncated).empty());
}

TEST_CASE("FNE SUID registration table tracks foreign units per peer", "[fne][roaming][suid]")
{
    SuidRegistrationTable table;
    const SUID a = { 0xDEE00U, 0x911U, 0x0F4240U };
    const SUID b = { 0xDEE00U, 0x911U, 0x000001U };
    SuidRegistrationTable::Entry entry;

    REQUIRE(table.registerUnit(a, 2001U));
    REQUIRE(table.find(a, entry));
    CHECK(entry.peerId == 2001U);
    CHECK(entry.registered);
    CHECK_FALSE(table.registerUnit(a, 0U));
    CHECK_FALSE(table.registerUnit(SUID{ 0x100000U, 0x911U, 1U }, 2001U));

    REQUIRE(table.affiliate(a, 2001U, 4001U));
    REQUIRE(table.find(a, entry));
    CHECK(entry.talkgroup == 4001U);

    // a deregistration from another peer is ignored
    CHECK_FALSE(table.deregisterUnit(a, 2002U));
    REQUIRE(table.unaffiliate(a, 2001U));
    REQUIRE(table.find(a, entry));
    CHECK(entry.talkgroup == 0U);
    REQUIRE(table.deregisterUnit(a, 2001U));
    CHECK_FALSE(table.find(a, entry));

    table.registerUnit(a, 2001U);
    table.registerUnit(b, 2001U);
    const std::vector<SUID> removed = table.replacePeerRegistrations(2001U, std::vector<SUID>({ a }));
    REQUIRE(removed.size() == 1U);
    CHECK(removed[0U] == b);
    CHECK(table.find(a, entry));
    CHECK_FALSE(table.find(b, entry));

    SuidAnnouncement aff;
    aff.suid = a;
    aff.talkgroup = 4002U;
    table.replacePeerAffiliations(2001U, std::vector<SuidAnnouncement>({ aff }));
    REQUIRE(table.find(a, entry));
    CHECK(entry.talkgroup == 4002U);
    table.replacePeerAffiliations(2001U, std::vector<SuidAnnouncement>());
    REQUIRE(table.find(a, entry));
    CHECK(entry.talkgroup == 0U);

    CHECK(table.erasePeer(2001U).size() == 1U);
    CHECK(table.snapshot().empty());
}

TEST_CASE("FNE accepts SUID announcements only from roaming-capable peers", "[fne][roaming][suid][announce]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    FNETestHooks::addPeer(harness.traffic, 2002U, network::NET_STAT_RUNNING, true);

    const SUID roamer = { 0xDEE00U, 0x911U, 0x0F4240U };
    const std::vector<uint8_t> unitBytes = { 0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };
    const std::vector<uint8_t> affilBytes = { 0x0FU, 0x42U, 0x40U, 0x00U, 0x0FU, 0xA1U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };
    auto announce = [&](uint32_t peerId, network::NET_SUBFUNC::ENUM subFunc, const std::vector<uint8_t>& payload) {
        FNETestHooks::dispatchMetadata(harness.traffic, harness.metadata, network::NET_FUNC::ANNOUNCE, subFunc, peerId, payload);
    };
    SuidRegistrationTable::Entry entry;

    // a peer that did not negotiate roaming is ignored (spec 3.4)
    announce(2002U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, unitBytes);
    CHECK_FALSE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));

    // malformed lengths change nothing (spec 6)
    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, std::vector<uint8_t>(unitBytes.begin(), unitBytes.end() - 1));
    CHECK_FALSE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));

    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, unitBytes);
    REQUIRE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(entry.peerId == 2001U);
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, roamer) == 2001U);

    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_GRP_AFFIL_SUID, affilBytes);
    REQUIRE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(entry.talkgroup == 4001U);

    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_GRP_UNAFFIL_SUID, unitBytes);
    REQUIRE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(entry.talkgroup == 0U);

    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_DEREG_SUID, unitBytes);
    CHECK_FALSE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, roamer) == 0U);

    // an own-system SUID is never accepted as a SUID announcement
    const std::vector<uint8_t> ownBytes = { 0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU };
    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, ownBytes);
    CHECK_FALSE(FNETestHooks::findSuidRegistration(harness.traffic, SUID{ 0xDEE00U, 0x13BU, 0x0F4240U }, entry));

    // bulk snapshots replace the peer's foreign registrations
    const SUID second = { 0xDEE00U, 0x911U, 0x000001U };
    std::vector<uint8_t> bulk = { 0x00U, 0x00U, 0x00U, 0x02U };
    bulk.insert(bulk.end(), unitBytes.begin(), unitBytes.end());
    const std::vector<uint8_t> secondBytes = { 0x00U, 0x00U, 0x01U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };
    bulk.insert(bulk.end(), secondBytes.begin(), secondBytes.end());
    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, bulk);
    CHECK(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(FNETestHooks::findSuidRegistration(harness.traffic, second, entry));

    std::vector<uint8_t> single = { 0x00U, 0x00U, 0x00U, 0x01U };
    single.insert(single.end(), unitBytes.begin(), unitBytes.end());
    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, single);
    CHECK(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK_FALSE(FNETestHooks::findSuidRegistration(harness.traffic, second, entry));
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, second) == 0U);

    // a count that disagrees with the length changes nothing
    std::vector<uint8_t> mismatch = { 0x00U, 0x00U, 0x00U, 0x05U };
    mismatch.insert(mismatch.end(), unitBytes.begin(), unitBytes.end());
    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, mismatch);
    CHECK(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));

    std::vector<uint8_t> affs = { 0x00U, 0x00U, 0x00U, 0x01U };
    affs.insert(affs.end(), affilBytes.begin(), affilBytes.end());
    announce(2001U, network::NET_SUBFUNC::ANNC_SUBFUNC_AFFILS_SUID, affs);
    REQUIRE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(entry.talkgroup == 4001U);

    // peer teardown removes the peer's foreign units and their routes
    REQUIRE(FNETestHooks::findSuidRoute(harness.traffic, roamer) == 2001U);
    FNETestHooks::teardownPeer(harness.traffic, 2001U);
    CHECK_FALSE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, roamer) == 0U);
}

TEST_CASE("FNE peer teardown clears foreign SUID routes when the peer has no affiliation lookup", "[fne][roaming][suid][announce]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));

    // addPeer() stores a connection only, so the peer has no affiliation lookup at teardown
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    FNETestHooks::addPeer(harness.traffic, 2002U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);

    const SUID roamer = { 0xDEE00U, 0x911U, 0x0F4240U };
    const SUID other = { 0xDEE00U, 0x911U, 0x000001U };
    const std::vector<uint8_t> unitBytes = { 0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };
    const std::vector<uint8_t> otherBytes = { 0x00U, 0x00U, 0x01U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };
    FNETestHooks::dispatchMetadata(harness.traffic, harness.metadata, network::NET_FUNC::ANNOUNCE,
        network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, 2001U, unitBytes);
    FNETestHooks::dispatchMetadata(harness.traffic, harness.metadata, network::NET_FUNC::ANNOUNCE,
        network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, 2002U, otherBytes);
    REQUIRE(FNETestHooks::findSuidRoute(harness.traffic, roamer) == 2001U);
    REQUIRE(FNETestHooks::findSuidRoute(harness.traffic, other) == 2002U);

    FNETestHooks::teardownPeer(harness.traffic, 2001U);
    SuidRegistrationTable::Entry entry;
    CHECK_FALSE(FNETestHooks::findSuidRegistration(harness.traffic, roamer, entry));
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, roamer) == 0U);

    // another peer's foreign route is untouched
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, other) == 2002U);
}

TEST_CASE("FNE dispatches ROAMING frames to the mobility service on negotiated links", "[fne][roaming][dispatch]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));                 // this FNE is the home of $911
    harness.radios.addEntry(0x0F4240U, true, "home roamer");

    const RoamingLink fne13B = { 2001U, false };
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    harness.traffic.roaming()->linkUp(fne13B, true, true, 0xDEE00U, 0x13BU);
    const RoamingLink oldPeer = { 2002U, false };
    FNETestHooks::addPeer(harness.traffic, 2002U, network::NET_STAT_RUNNING, true);
    harness.traffic.roaming()->linkUp(oldPeer, false, false, 0U, 0U);

    std::vector<FNETestHooks::PeerWrite> writes;
    FNETestHooks::capturePeerWriteData(harness.traffic, writes);

    // ROAM_SERVING_REG known-answer bytes (Task 2): $DEE00.$911.0F4240 served by $DEE00.$13B RFSS 1
    const std::vector<uint8_t> reg = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U, 0x01U };
    const std::vector<uint8_t> expectedRsp = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x00U, 0x00U, 0x00U, 0x46U, 0x50U, 0x01U, 0x00U };

    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2001U, reg);
    REQUIRE(writes.size() == 1U);
    CHECK(writes[0U].peerId == 2001U);
    CHECK(writes[0U].function == network::NET_FUNC::ROAMING);
    CHECK(writes[0U].subFunction == network::NET_SUBFUNC::ROAM_SERVING_REG_RSP);
    CHECK(writes[0U].data == expectedRsp);
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, SUID{ 0xDEE00U, 0x911U, 0x0F4240U }) == 2001U);
    REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);

    // a link that did not negotiate roaming is ignored
    writes.clear();
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2002U, reg);
    CHECK(writes.empty());

    // the SU registering on one of this system's own sites deregisters the serving RFSS (Roamed)
    FNETestHooks::registerP25Unit(harness.traffic, 501U, 0x0F4240U);
    REQUIRE(writes.size() == 1U);
    CHECK(writes[0U].peerId == 2001U);
    CHECK(writes[0U].subFunction == network::NET_SUBFUNC::ROAM_HOME_DEREG);
    REQUIRE(writes[0U].data.size() == MSG_ROAM_HOME_DEREG_LEN);
    CHECK(writes[0U].data[14U] == RoamQualifier::ROAMED);
    CHECK(harness.traffic.roaming()->homeRecords().empty());

    // peer teardown drops the link
    FNETestHooks::teardownPeer(harness.traffic, 2001U);
    CHECK_FALSE(harness.traffic.roaming()->isLinkCapable(fne13B));
}

TEST_CASE("FNE ignores unit registrations from a neighbor FNE for the home-site deregistration", "[fne][roaming][dispatch]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));
    harness.radios.addEntry(0x0F4240U, true, "home roamer");

    const RoamingLink fne13B = { 2001U, false };
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    harness.traffic.roaming()->linkUp(fne13B, true, true, 0xDEE00U, 0x13BU);
    network::FNEPeerConnection& neighbor = FNETestHooks::addPeer(harness.traffic, 2003U, network::NET_STAT_RUNNING, true);
    neighbor.peerClass(network::PEER_CONN_CLASS_NEIGHBOR);

    std::vector<FNETestHooks::PeerWrite> writes;
    FNETestHooks::capturePeerWriteData(harness.traffic, writes);

    const std::vector<uint8_t> reg = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U, 0x01U };
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2001U, reg);
    REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);
    writes.clear();

    // a neighbor FNE is another system: its bare Unit IDs are not registrations on a home site of this system
    FNETestHooks::registerP25Unit(harness.traffic, 2003U, 0x0F4240U);
    CHECK(writes.empty());
    CHECK(harness.traffic.roaming()->homeRecords().size() == 1U);
}

TEST_CASE("FNE does not record unit routes for registrations arriving from an upstream link", "[fne][roaming][dispatch]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));                 // this FNE is the home of $911
    harness.radios.addEntry(0x0F4240U, true, "home roamer");

    // the upstream link's ID is a PeerNetwork key; give it the value of a real downstream peer to catch a collision
    const RoamingLink upstream = { 2001U, true };
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true);
    harness.traffic.roaming()->linkUp(upstream, true, true, 0xDEE00U, 0x13BU);

    const std::vector<uint8_t> reg = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U, 0x01U };
    harness.traffic.processUpstreamRoaming(2001U, network::NET_SUBFUNC::ROAM_SERVING_REG, reg.data(), static_cast<uint32_t>(reg.size()));

    // the home record exists but the upstream key is not written into the (downstream peer) unit route table
    REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, SUID{ 0xDEE00U, 0x911U, 0x0F4240U }) == 0U);
    CHECK(FNETestHooks::findPeerUnitReg(harness.traffic, 0x0F4240U) == 0U);

    // dropping the upstream link leaves no stale route
    harness.traffic.roaming()->linkDown(upstream);
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, SUID{ 0xDEE00U, 0x911U, 0x0F4240U }) == 0U);
}

TEST_CASE("FNE keeps a roamed home unit's route SUID-only so bare Unit ID lookups never pick the neighbor link", "[fne][roaming][route]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));                 // this FNE is the home of $911
    harness.radios.addEntry(0x0F4240U, true, "home roamer");
    FNETestHooks::configurePrivateCallRouting(harness.traffic, true, "reject", false, 0U);

    // the SU roams to system $13B behind a neighbor FNE link
    const RoamingLink fne13B = { 2001U, false };
    network::FNEPeerConnection& neighbor = FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true);
    neighbor.peerClass(network::PEER_CONN_CLASS_NEIGHBOR);
    neighbor.p25RoamingCapable(true);
    harness.traffic.roaming()->linkUp(fne13B, true, true, 0xDEE00U, 0x13BU);

    const std::vector<uint8_t> reg = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U, 0x01U };
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2001U, reg);
    REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);

    // the roaming route is kept by full SUID for the location data
    const SUID home = { 0xDEE00U, 0x911U, 0x0F4240U };
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, home) == 2001U);

    // bare Unit ID consumers (REST/SubscriberOperation targets, U2U availability and routing) behave as before roaming:
    //  the unit is unknown here and never addressed by bare ID on the foreign system
    CHECK(FNETestHooks::findPeerUnitReg(harness.traffic, 0x0F4240U) == 0U);
    CHECK_FALSE(FNETestHooks::isUnitRouteAvailable(harness.traffic, 0x0F4240U));

    // a local re-registration restores the normal bare route
    FNETestHooks::registerP25Unit(harness.traffic, 501U, 0x0F4240U);
    CHECK(FNETestHooks::findPeerUnitReg(harness.traffic, 0x0F4240U) == 501U);
    CHECK(FNETestHooks::isUnitRouteAvailable(harness.traffic, 0x0F4240U));
    CHECK(FNETestHooks::findSuidRoute(harness.traffic, home) == 501U);
    CHECK(harness.traffic.roaming()->homeRecords().empty());
}

TEST_CASE("FNE does not treat a traffic-learned unit route as a home-site registration", "[fne][roaming][dispatch]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));                 // this FNE is the home of $911
    harness.radios.addEntry(0x0F4240U, true, "home roamer");
    FNETestHooks::configurePrivateCallRouting(harness.traffic, true, "reject", true, 300000U);

    const RoamingLink fne13B = { 2001U, false };
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    harness.traffic.roaming()->linkUp(fne13B, true, true, 0xDEE00U, 0x13BU);

    // a home site with an existing registration table (another unit registered there)
    FNETestHooks::addPeer(harness.traffic, 501U, network::NET_STAT_RUNNING, true);
    FNETestHooks::registerP25Unit(harness.traffic, 501U, 1234U);

    const std::vector<uint8_t> reg = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U, 0x01U };
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2001U, reg);
    REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);

    std::vector<FNETestHooks::PeerWrite> writes;
    FNETestHooks::capturePeerWriteData(harness.traffic, writes);

    // traffic carrying the same bare Unit ID through a home site is not a P25 registration on that site
    FNETestHooks::learnUnitRoute(harness.traffic, 501U, 0x0F4240U, 501U);
    for (const FNETestHooks::PeerWrite& write : writes) {
        CHECK(write.subFunction != network::NET_SUBFUNC::ROAM_HOME_DEREG);
    }
    CHECK(harness.traffic.roaming()->homeRecords().size() == 1U);
}

TEST_CASE("FNE releases a roamed home unit only on a P25-tagged unit registration from a host", "[fne][roaming][dispatch][announce]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));                 // this FNE is the home of $911
    harness.radios.addEntry(0x0F4240U, true, "home roamer");

    const RoamingLink fne13B = { 2001U, false };
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    harness.traffic.roaming()->linkUp(fne13B, true, true, 0xDEE00U, 0x13BU);

    // a home site with a registration table (another unit registered there)
    FNETestHooks::addPeer(harness.traffic, 501U, network::NET_STAT_RUNNING, true);
    FNETestHooks::registerP25Unit(harness.traffic, 501U, 1234U);

    const std::vector<uint8_t> reg = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U, 0x01U };
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2001U, reg);
    REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);

    std::vector<FNETestHooks::PeerWrite> writes;
    FNETestHooks::capturePeerWriteData(harness.traffic, writes);
    auto announceReg = [&](const std::vector<uint8_t>& payload) {
        FNETestHooks::dispatchMetadata(harness.traffic, harness.metadata, network::NET_FUNC::ANNOUNCE,
            network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG, 501U, payload);
    };
    auto homeDeregs = [&]() {
        return std::count_if(writes.begin(), writes.end(), [](const FNETestHooks::PeerWrite& write) {
            return write.subFunction == network::NET_SUBFUNC::ROAM_HOME_DEREG;
        });
    };

    // radios share unit numbers across protocols: a DMR, NXDN or untagged (older host) registration of the same
    //  Unit ID is a different radio and never ends the P25 roamer's serving registration
    announceReg({ 0x0FU, 0x42U, 0x40U, 0x00U });                                    // DMR
    CHECK(FNETestHooks::peerAffiliations(harness.traffic, 501U)->isUnitReg(0x0F4240U));
    CHECK(homeDeregs() == 0);
    CHECK(harness.traffic.roaming()->homeRecords().size() == 1U);

    announceReg({ 0x0FU, 0x42U, 0x40U, 0x02U });                                    // NXDN
    CHECK(homeDeregs() == 0);
    CHECK(harness.traffic.roaming()->homeRecords().size() == 1U);

    announceReg({ 0x0FU, 0x42U, 0x40U });                                           // untagged 3-byte form
    CHECK(FNETestHooks::peerAffiliations(harness.traffic, 501U)->isUnitReg(0x0F4240U));
    CHECK(homeDeregs() == 0);
    CHECK(harness.traffic.roaming()->homeRecords().size() == 1U);

    // a P25-tagged registration on the home site deregisters the serving RFSS (Roamed, BACA 5.1)
    announceReg({ 0x0FU, 0x42U, 0x40U, 0x01U });                                    // P25
    REQUIRE(homeDeregs() == 1);
    CHECK(writes.back().peerId == 2001U);
    REQUIRE(writes.back().data.size() == MSG_ROAM_HOME_DEREG_LEN);
    CHECK(writes.back().data[14U] == RoamQualifier::ROAMED);
    CHECK(harness.traffic.roaming()->homeRecords().empty());
}

TEST_CASE("FNE finds a home unit's local registration for release only when it is P25-tagged", "[fne][roaming][route]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));
    FNETestHooks::configurePrivateCallRouting(harness.traffic, true, "reject", true, 300000U);

    const uint32_t unit = 0x0F4240U;
    FNETestHooks::addPeer(harness.traffic, 501U, network::NET_STAT_RUNNING, true);
    FNETestHooks::registerP25Unit(harness.traffic, 501U, 1234U);
    FNETestHooks::addPeer(harness.traffic, 502U, network::NET_STAT_RUNNING, true);
    FNETestHooks::registerP25Unit(harness.traffic, 502U, 1235U);
    auto announceReg = [&](uint32_t peerId, const std::vector<uint8_t>& payload) {
        FNETestHooks::dispatchMetadata(harness.traffic, harness.metadata, network::NET_FUNC::ANNOUNCE,
            network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG, peerId, payload);
    };

    // DMR, NXDN and untagged registrations route the bare Unit ID but are never released by P25 roaming
    announceReg(501U, { 0x0FU, 0x42U, 0x40U, 0x00U });
    CHECK(FNETestHooks::findPeerUnitReg(harness.traffic, unit) == 501U);
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 0U);
    announceReg(501U, { 0x0FU, 0x42U, 0x40U, 0x02U });
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 0U);
    announceReg(501U, { 0x0FU, 0x42U, 0x40U });
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 0U);

    announceReg(501U, { 0x0FU, 0x42U, 0x40U, 0x01U });
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 501U);

    // a later DMR registration of the same Unit ID replaces the P25 one
    announceReg(501U, { 0x0FU, 0x42U, 0x40U, 0x00U });
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 0U);

    // traffic through the registered site keeps the P25 registration; traffic through another site replaces it
    announceReg(501U, { 0x0FU, 0x42U, 0x40U, 0x01U });
    FNETestHooks::learnUnitRoute(harness.traffic, 501U, unit, 501U);
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 501U);
    FNETestHooks::learnUnitRoute(harness.traffic, 502U, unit, 502U);
    CHECK(FNETestHooks::findPeerUnitReg(harness.traffic, unit) == 502U);
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 0U);

    // the bulk snapshot carries no protocol: it keeps an existing P25 registration on the same site and creates
    //  untagged ones
    announceReg(501U, { 0x0FU, 0x42U, 0x40U, 0x01U });
    REQUIRE(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 501U);
    REQUIRE(FNETestHooks::replaceUnitRegistrations(harness.traffic, 501U, { unit, 1234U, 2222U }, 501U));
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 501U);
    CHECK(FNETestHooks::findPeerUnitReg(harness.traffic, 2222U) == 501U);
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, 2222U) == 0U);

    // a snapshot from another site replaces the route and is untagged
    REQUIRE(FNETestHooks::replaceUnitRegistrations(harness.traffic, 502U, { unit, 1235U }, 502U));
    CHECK(FNETestHooks::findPeerUnitReg(harness.traffic, unit) == 502U);
    CHECK(FNETestHooks::findLocalUnitPeer(harness.traffic, unit) == 0U);
}

TEST_CASE("FNE serving registration leaves a DMR registration of the same Unit ID at a home site", "[fne][roaming][dispatch]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x911U));                 // this FNE is the home of $911
    harness.radios.addEntry(0x0F4240U, true, "home roamer");

    const RoamingLink fne13B = { 2001U, false };
    FNETestHooks::addPeer(harness.traffic, 2001U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    harness.traffic.roaming()->linkUp(fne13B, true, true, 0xDEE00U, 0x13BU);

    // a roaming-capable home site, so a release would also send it a Home Deregistration
    const RoamingLink site = { 501U, false };
    FNETestHooks::addPeer(harness.traffic, 501U, network::NET_STAT_RUNNING, true).p25RoamingCapable(true);
    harness.traffic.roaming()->linkUp(site, true, false, 0xDEE00U, 0x911U);
    FNETestHooks::registerP25Unit(harness.traffic, 501U, 1234U);

    const std::vector<uint8_t> reg = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U,
        0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U, 0x01U };
    std::vector<FNETestHooks::PeerWrite> writes;

    SECTION("DMR registration is kept") {
        FNETestHooks::dispatchMetadata(harness.traffic, harness.metadata, network::NET_FUNC::ANNOUNCE,
            network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG, 501U, { 0x0FU, 0x42U, 0x40U, 0x00U });
        FNETestHooks::capturePeerWriteData(harness.traffic, writes);

        FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2001U, reg);
        REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);
        for (const FNETestHooks::PeerWrite& write : writes) {
            CHECK(write.peerId != 501U);
        }
        CHECK(FNETestHooks::peerAffiliations(harness.traffic, 501U)->isUnitReg(0x0F4240U));
    }

    SECTION("P25 registration is released") {
        FNETestHooks::dispatchMetadata(harness.traffic, harness.metadata, network::NET_FUNC::ANNOUNCE,
            network::NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG, 501U, { 0x0FU, 0x42U, 0x40U, 0x01U });
        FNETestHooks::capturePeerWriteData(harness.traffic, writes);

        FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::ROAMING, network::NET_SUBFUNC::ROAM_SERVING_REG, 2001U, reg);
        REQUIRE(harness.traffic.roaming()->homeRecords().size() == 1U);
        const bool siteDereg = std::any_of(writes.begin(), writes.end(), [](const FNETestHooks::PeerWrite& write) {
            return write.peerId == 501U && write.subFunction == network::NET_SUBFUNC::ROAM_HOME_DEREG;
        });
        CHECK(siteDereg);
        CHECK_FALSE(FNETestHooks::peerAffiliations(harness.traffic, 501U)->isUnitReg(0x0F4240U));
    }
}

TEST_CASE("FNE treats a downstream FNE offering this system's own identity as not roaming capable", "[fne][roaming][login]")
{
    // exactly one FNE per system (WACN + System ID) holds the identity: the home (one Home RFSS per SU)
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
    network::FNEPeerConnection& neighbor = FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
        rptcPacket("{\"identity\": \"FNE315B\", \"peerClass\": 1, \"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 0}}"));

    // the login is accepted, but the link never negotiates roaming
    REQUIRE(FNETestHooks::hasPeer(harness.traffic, 1001U));
    CHECK(FNETestHooks::peerState(harness.traffic, 1001U) == network::NET_STAT_RUNNING);
    CHECK(neighbor.peerClass() == network::PEER_CONN_CLASS_NEIGHBOR);
    CHECK_FALSE(neighbor.p25RoamingCapable());
    CHECK_FALSE(harness.traffic.roaming()->isLinkCapable(RoamingLink{ 1001U, false }));
}

TEST_CASE("FNE rejects a downstream FNE offering a protected BEE00 - BEEFF WACN", "[fne][roaming][login]")
{
    // the same protection as this FNE's own p25NetId: subscribers must never roam onto a BEExx system
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
    FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
        rptcPacket("{\"identity\": \"FNEBEE\", \"peerClass\": 1, \"p25Roaming\": {\"version\": 1, \"netId\": 781824, \"sysId\": 2321, \"rfssId\": 0}}"));
    CHECK_FALSE(FNETestHooks::hasPeer(harness.traffic, 1001U));

    // the last WACN of the range is protected too; the first WACN past it is not
    FNETestHooks::addPeer(harness.traffic, 1002U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1002U,
        rptcPacket("{\"identity\": \"FNEBEEFF\", \"peerClass\": 1, \"p25Roaming\": {\"version\": 1, \"netId\": 782079, \"sysId\": 2321, \"rfssId\": 0}}"));
    CHECK_FALSE(FNETestHooks::hasPeer(harness.traffic, 1002U));

    network::FNEPeerConnection& next = FNETestHooks::addPeer(harness.traffic, 1003U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1003U,
        rptcPacket("{\"identity\": \"FNEBEF00\", \"peerClass\": 1, \"p25Roaming\": {\"version\": 1, \"netId\": 782080, \"sysId\": 2321, \"rfssId\": 0}}"));
    REQUIRE(FNETestHooks::hasPeer(harness.traffic, 1003U));
    CHECK(next.p25RoamingCapable());
}

TEST_CASE("FNE RPTC handler answers with the exact roaming ACK and identity-mismatch NAK bytes", "[fne][roaming][login]")
{
    RoamingFNEHarness harness;
    harness.traffic.setP25RoamingConfig(configFor(0xDEE00U, 0x13BU));
    std::vector<FNETestHooks::PeerWrite> writes;
    FNETestHooks::capturePeerWriteData(harness.traffic, writes);

    // ACK: peer ID (4), 2 zero bytes, then the 6-byte roaming payload (spec 3.1) and the 4-byte zero trailer
    FNETestHooks::addPeer(harness.traffic, 1001U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1001U,
        rptcPacket("{\"identity\": \"SITE315\", \"peerClass\": 0, \"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 2}}"));
    const FNETestHooks::PeerWrite* ack = nullptr;
    for (const FNETestHooks::PeerWrite& write : writes) {
        if (write.peerId == 1001U && write.function == network::NET_FUNC::ACK) {
            ack = &write;
        }
    }
    REQUIRE(ack != nullptr);
    CHECK(ack->data == std::vector<uint8_t>({ 0x00U, 0x00U, 0x03U, 0xE9U, 0x00U, 0x00U,
        0xC0U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x00U, 0x00U, 0x00U, 0x00U }));

    // NAK: 6 zero bytes, peer ID (4), reason NET_CONN_NAK_INVALID_CONFIG_DATA (2)
    writes.clear();
    FNETestHooks::addPeer(harness.traffic, 1002U, network::NET_STAT_WAITING_CONFIG);
    FNETestHooks::dispatchTraffic(harness.traffic, network::NET_FUNC::RPTC, network::NET_SUBFUNC::NOP, 1002U,
        rptcPacket("{\"identity\": \"SITE911\", \"peerClass\": 0, \"p25Roaming\": {\"version\": 1, \"netId\": 912896, \"sysId\": 2321, \"rfssId\": 1}}"));
    REQUIRE(writes.size() == 1U);
    CHECK(writes[0U].peerId == 1002U);
    CHECK(writes[0U].function == network::NET_FUNC::NAK);
    CHECK(writes[0U].data == std::vector<uint8_t>({ 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x03U, 0xEAU, 0x00U, (uint8_t)network::NET_CONN_NAK_INVALID_CONFIG_DATA }));
    CHECK(network::NET_CONN_NAK_INVALID_CONFIG_DATA == 5);
    CHECK_FALSE(FNETestHooks::hasPeer(harness.traffic, 1002U));
}
