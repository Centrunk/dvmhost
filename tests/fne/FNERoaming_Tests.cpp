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
