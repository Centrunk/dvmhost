// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 Bryan Biedenkapp, N2PLL
 */

#include <catch2/catch_test_macros.hpp>

#include "common/edac/SHA256.h"
#include "common/lookups/RadioAliasLookup.h"
#include "common/lookups/RadioIdLookup.h"
#include "common/lookups/AdjSiteMapLookup.h"
#include "common/lookups/PeerListLookup.h"
#include "common/lookups/TalkgroupRulesLookup.h"
#include "common/restapi/http/HTTPPayload.h"
#include "common/network/P25Roaming.h"
#include "common/network/RTPFNEHeader.h"
#include "fne/FNETestHooks.h"
#include "fne/HostFNE.h"
#include "fne/network/RoamingService.h"
#include "fne/network/TrafficNetwork.h"
#include "fne/restapi/RESTAPI.h"
#include "fne/restapi/RESTDefines.h"
#include "remote/RESTClient.h"

#include <asio.hpp>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace restapi::http;
using namespace fne_restapi;

namespace {
    // ---------------------------------------------------------------------------
    //  Global Variables
    // ---------------------------------------------------------------------------

    constexpr uint32_t TEST_RID = 123456U;
    const std::string TEST_PASSWORD = "fne-rest-test-password";

    // ---------------------------------------------------------------------------
    //  Global Functions
    // ---------------------------------------------------------------------------

    /**
     * @brief Reserves an available loopback port.
     * @returns uint16_t 
     */
    uint16_t reserveLoopbackPort()
    {
        asio::io_service ioService;
        asio::ip::tcp::acceptor acceptor(ioService,
            asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0U));
        return acceptor.local_endpoint().port();
    }

    /**
     * @brief Generates a temporary file path for the ACL file.
     * @returns std::string 
     */
    std::string temporaryACLPath()
    {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        return "/tmp/dvm-fne-rest-rid-" + std::to_string(stamp) + ".csv";
    }

    /**
     * @brief Reads the contents of a lookup file, returning an empty string if it does not exist.
     * @param path The lookup file path.
     * @returns std::string
     */
    std::string readFileContents(const std::string& path)
    {
        std::ifstream file(path);
        return std::string((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
    }

    /** 
     * @brief Sends a REST API request to the specified endpoint with the given payload.
     * @param port The port on which the REST API server is running.
     * @param method The HTTP method to use for the request.
     * @param endpoint The REST API endpoint to send the request to.
     * @param payload The JSON payload to include in the request.
     * @return The JSON response from the server.
     */
    json::object sendRequest(uint16_t port, const std::string& method,
        const std::string& endpoint, json::object payload = json::object())
    {
        json::object response = json::object();
        REQUIRE(RESTClient::send("127.0.0.1", port, TEST_PASSWORD, method, endpoint,
            payload, response, false, 1000, false) == HTTPPayload::OK);
        REQUIRE(response["status"].get<int>() == HTTPPayload::OK);
        return response;
    }

    /**
     * @brief Result of a raw HTTP exchange with the REST server.
     */
    struct RawResponse {
        int httpStatus = 0;                             //!< HTTP status code of the response line.
        json::object body;                              //!< Parsed JSON response body.
    };

    /**
     * @brief Sends one raw HTTP request, allowing an arbitrary (possibly malformed) body.
     * @param port The port on which the REST API server is running.
     * @param method The HTTP method.
     * @param endpoint The REST API endpoint.
     * @param token Authentication token, or empty for none.
     * @param content Raw request body.
     * @returns RawResponse The HTTP status and parsed JSON body.
     */
    RawResponse sendRaw(uint16_t port, const std::string& method, const std::string& endpoint,
        const std::string& token, const std::string& content)
    {
        asio::io_service ioService;
        asio::ip::tcp::socket socket(ioService);
        socket.connect(asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port));

        std::string request = method + " " + endpoint + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
        if (!token.empty())
            request += "X-DVM-Auth-Token: " + token + "\r\n";
        request += "Content-Type: application/json\r\nContent-Length: " + std::to_string(content.size()) + "\r\n\r\n" + content;
        asio::write(socket, asio::buffer(request));

        asio::streambuf buffer;
        asio::read_until(socket, buffer, "\r\n\r\n");
        std::istream stream(&buffer);

        RawResponse result;
        std::string line;
        std::getline(stream, line);
        REQUIRE(line.compare(0U, 9U, "HTTP/1.0 ") == 0);
        result.httpStatus = std::stoi(line.substr(9U, 3U));

        size_t length = 0U;
        while (std::getline(stream, line) && line != "\r") {
            if (line.compare(0U, 15U, "Content-Length:") == 0)
                length = std::stoul(line.substr(15U));
        }

        std::string body((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        if (body.size() < length) {
            std::string rest(length - body.size(), '\0');
            asio::read(socket, asio::buffer(&rest[0], rest.size()));
            body += rest;
        }

        json::value value;
        REQUIRE(json::parse(value, body).empty());
        result.body = value.get<json::object>();
        return result;
    }

    /**
     * @brief Authenticates against the REST server over a raw socket.
     * @param port The port on which the REST API server is running.
     * @returns std::string Authentication token.
     */
    std::string authenticateRaw(uint16_t port)
    {
        uint8_t hash[32U];
        edac::SHA256 sha256;
        sha256.buffer(reinterpret_cast<const uint8_t*>(TEST_PASSWORD.data()), static_cast<uint32_t>(TEST_PASSWORD.size()), hash);

        char hex[65U];
        for (uint32_t i = 0U; i < 32U; i++)
            ::snprintf(hex + (i * 2U), 3U, "%02x", hash[i]);

        RawResponse rsp = sendRaw(port, HTTP_PUT, "/auth", "", std::string("{\"auth\":\"") + hex + "\"}");
        REQUIRE(rsp.httpStatus == 200);
        return rsp.body["token"].get<std::string>();
    }

    /**
     * @brief Creates a JSON payload for a talkgroup with the specified parameters.
     * @param tgid The talkgroup ID.
     * @param slot The slot number.
     * @param name The name of the talkgroup.
     * @return The JSON object representing the talkgroup.
     */
    json::object talkgroupPayload(uint32_t tgid, uint8_t slot, const std::string& name)
    {
        json::object source = json::object();
        source["tgid"].set<uint32_t>(tgid);
        source["slot"].set<uint8_t>(slot);

        json::object config = json::object();
        config["active"] = json::value(true);
        config["affiliated"] = json::value(false);
        config["parrot"] = json::value(false);
        config["strapping"] = json::value((double)lookups::TG_STRAPPING_SELECTABLE);
        config["inclusion"].set<json::array>(json::array());
        config["exclusion"].set<json::array>(json::array());
        config["rewrite"].set<json::array>(json::array());
        config["always"].set<json::array>(json::array());
        config["preferred"].set<json::array>(json::array());
        config["permittedRids"].set<json::array>(json::array());

        json::object tg = json::object();
        tg["name"].set<std::string>(name);
        tg["alias"].set<std::string>(name + " alias");
        tg["source"].set<json::object>(source);
        tg["config"].set<json::object>(config);
        return tg;
    }

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Scoped wrapper for a temporary ACL file.
     */
    class ScopedACLFile {
    public:
        /**
         * @brief Initializes a new instance of the ScopedACLFile class.
         */
        ScopedACLFile() : path(temporaryACLPath()) { }
        /**
         * @brief Finalizes a instance of the ScopedACLFile class.
         */
        ~ScopedACLFile() { std::remove(path.c_str()); }

        std::string path;
    };

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Scoped wrapper for the RESTAPI instance used in tests.
     */
    class ScopedRESTAPI {
    public:
        /**
         * @brief Initializes a new instance of the ScopedRESTAPI class.
         * @param port The port on which the REST API server will listen.
         * @param ridLookup The Radio ID lookup instance.
         * @param ridAliasLookup The Radio Alias lookup instance.
         * @param tgLookup The Talkgroup Rules lookup instance.
         * @param peerLookup The Peer List lookup instance.
         * @param adjLookup The Adjacent Site Map lookup instance.
         */
        ScopedRESTAPI(uint16_t port, lookups::RadioIdLookup* ridLookup = nullptr,
            lookups::RadioAliasLookup* ridAliasLookup = nullptr,
            lookups::TalkgroupRulesLookup* tgLookup = nullptr,
            lookups::PeerListLookup* peerLookup = nullptr,
            lookups::AdjSiteMapLookup* adjLookup = nullptr) :
            api("127.0.0.1", port, TEST_PASSWORD, "", "", false, nullptr, false)
        {
            api.setLookups(ridLookup, ridAliasLookup, tgLookup, peerLookup, adjLookup, nullptr);
            REQUIRE(api.open());
        }
        /**
         * @brief Finalizes a instance of the ScopedRESTAPI class.
         */
        ~ScopedRESTAPI() { api.close(); }

        fne_restapi::RESTAPI api;
    };
} // namespace


TEST_CASE("FNE REST RID add and commit updates the persisted ACL", "[fne][restapi][rid]")
{
    ScopedACLFile aclFile;
    lookups::RadioIdLookup lookup(aclFile.path, 0U, true);
    const std::string initialContents = readFileContents(aclFile.path);
    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, &lookup);

    json::object add = json::object();
    add["rid"] = json::value((double)TEST_RID);
    add["enabled"] = json::value(true);
    add["alias"].set<std::string>("REST test radio");
    add["canRequestKeys"] = json::value(true);
    add["canRekey"] = json::value(true);
    json::array allowedKIds = json::array();
    allowedKIds.push_back(json::value((double)0x1234U));
    allowedKIds.push_back(json::value((double)0xABCDU));
    add["allowedKIds"].set<json::array>(allowedKIds);

    sendRequest(port, HTTP_PUT, FNE_PUT_RID_ADD, add);
    CHECK(readFileContents(aclFile.path) == initialContents);

    const lookups::RadioId added = lookup.find(TEST_RID);
    REQUIRE_FALSE(added.radioDefault());
    CHECK(added.radioEnabled());
    CHECK(added.radioAlias() == "REST test radio");
    CHECK(added.canRequestKeys());
    CHECK(added.canRekey());
    CHECK(added.allowedKIds() == std::vector<uint16_t> { 0x1234U, 0xABCDU });

    sendRequest(port, HTTP_GET, FNE_GET_RID_COMMIT);
    const std::string committedContents = readFileContents(aclFile.path);
    CHECK(committedContents != initialContents);
    CHECK(committedContents.find(std::to_string(TEST_RID)) != std::string::npos);

    lookups::RadioIdLookup persisted(aclFile.path, 0U, true);
    REQUIRE(persisted.read());
    const lookups::RadioId saved = persisted.find(TEST_RID);
    REQUIRE_FALSE(saved.radioDefault());
    CHECK(saved.radioAlias() == "REST test radio");
    CHECK(saved.allowedKIds() == std::vector<uint16_t> { 0x1234U, 0xABCDU });
}

TEST_CASE("FNE REST RID delete and commit removes the RID from the ACL", "[fne][restapi][rid]")
{
    ScopedACLFile aclFile;
    lookups::RadioIdLookup lookup(aclFile.path, 0U, true);
    lookup.addEntry(TEST_RID, true, "radio to delete");
    lookup.commit(true);
    const std::string committedContents = readFileContents(aclFile.path);

    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, &lookup);

    json::object remove = json::object();
    remove["rid"] = json::value((double)TEST_RID);
    sendRequest(port, HTTP_PUT, FNE_PUT_RID_DELETE, remove);
    CHECK(lookup.find(TEST_RID).radioDefault());
    CHECK(readFileContents(aclFile.path) == committedContents);

    sendRequest(port, HTTP_GET, FNE_GET_RID_COMMIT);
    const std::string contents = readFileContents(aclFile.path);
    CHECK(contents != committedContents);
    CHECK(contents.find(std::to_string(TEST_RID)) == std::string::npos);
}

TEST_CASE("FNE REST RID alias endpoints query, persist, and delete aliases", "[fne][restapi][rid][alias]")
{
    ScopedACLFile aliasFile;
    lookups::RadioAliasLookup lookup(aliasFile.path, 0U, true);
    const std::string initialContents = readFileContents(aliasFile.path);
    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, nullptr, &lookup);

    json::object add = json::object();
    add["rid"] = json::value((double)TEST_RID);
    add["alias"].set<std::string>("REST test alias");
    sendRequest(port, HTTP_PUT, FNE_PUT_RID_ALIAS_ADD, add);

    CHECK(lookup.find(TEST_RID) == "REST test alias");
    CHECK(readFileContents(aliasFile.path) == initialContents);

    json::object query = sendRequest(port, HTTP_GET, FNE_GET_RID_ALIAS_QUERY);
    const json::array aliases = query["rids"].get<json::array>();
    REQUIRE(aliases.size() == 1U);
    json::object queriedAlias = aliases[0U].get<json::object>();
    CHECK(queriedAlias["id"].get<uint32_t>() == TEST_RID);
    CHECK(queriedAlias["alias"].get<std::string>() == "REST test alias");

    sendRequest(port, HTTP_GET, FNE_GET_RID_ALIAS_COMMIT);
    const std::string committedContents = readFileContents(aliasFile.path);
    CHECK(committedContents != initialContents);
    CHECK(committedContents.find(std::to_string(TEST_RID)) != std::string::npos);

    lookups::RadioAliasLookup persisted(aliasFile.path, 0U, true);
    REQUIRE(persisted.read());
    CHECK(persisted.find(TEST_RID) == "REST test alias");

    json::object remove = json::object();
    remove["rid"] = json::value((double)TEST_RID);
    sendRequest(port, HTTP_PUT, FNE_PUT_RID_ALIAS_DELETE, remove);
    CHECK(lookup.find(TEST_RID) == "UNKNOWN");
    CHECK(readFileContents(aliasFile.path) == committedContents);

    sendRequest(port, HTTP_GET, FNE_GET_RID_ALIAS_COMMIT);
    const std::string contents = readFileContents(aliasFile.path);
    CHECK(contents != committedContents);
    CHECK(contents.find(std::to_string(TEST_RID)) == std::string::npos);
}

TEST_CASE("FNE REST peer endpoints query, persist, and delete ACL entries", "[fne][restapi][peer]")
{
    ScopedACLFile aclFile;
    lookups::PeerListLookup lookup(aclFile.path, 0U, true, false);
    const std::string initialContents = readFileContents(aclFile.path);
    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, nullptr, nullptr, nullptr, &lookup);

    json::object add = json::object();
    add["peerId"] = json::value((double)9001U);
    add["peerAlias"].set<std::string>("REST peer");
    add["peerPassword"].set<std::string>("peer secret");
    add["peerReplica"] = json::value(true);
    add["canRequestKeys"] = json::value(true);
    add["canIssueInhibit"] = json::value(true);
    add["hasCallPriority"] = json::value(true);
    add["telephoneInterconnect"] = json::value(true);
    add["allowUnitToUnit"] = json::value(false);
    sendRequest(port, HTTP_PUT, FNE_PUT_PEER_ADD, add);
    CHECK(readFileContents(aclFile.path) == initialContents);

    const lookups::PeerId peer = lookup.find(9001U);
    CHECK(peer.peerAlias() == "REST peer");
    CHECK(peer.peerPassword() == "peer secret");
    CHECK(peer.peerReplica());
    CHECK(peer.canRequestKeys());
    CHECK(peer.canIssueInhibit());
    CHECK(peer.hasCallPriority());
    CHECK(peer.telephoneInterconnect());
    CHECK_FALSE(peer.allowUnitToUnit());

    json::object query = sendRequest(port, HTTP_GET, FNE_GET_PEER_LIST);
    REQUIRE(query["peers"].get<json::array>().size() == 1U);
    CHECK(query["peers"].get<json::array>()[0U].get<json::object>()["peerPassword"].get<bool>());
    CHECK(query["peers"].get<json::array>()[0U].get<json::object>()["telephoneInterconnect"].get<bool>());
    CHECK_FALSE(query["peers"].get<json::array>()[0U].get<json::object>()["allowUnitToUnit"].get<bool>());

    sendRequest(port, HTTP_GET, FNE_GET_PEER_COMMIT);
    const std::string committedContents = readFileContents(aclFile.path);
    CHECK(committedContents != initialContents);
    CHECK(committedContents.find("9001") != std::string::npos);
    lookups::PeerListLookup persisted(aclFile.path, 0U, true, false);
    REQUIRE(persisted.read());
    CHECK(persisted.find(9001U).peerAlias() == "REST peer");

    json::object remove = json::object();
    remove["peerId"] = json::value((double)9001U);
    sendRequest(port, HTTP_PUT, FNE_PUT_PEER_DELETE, remove);
    CHECK(readFileContents(aclFile.path) == committedContents);
    sendRequest(port, HTTP_GET, FNE_GET_PEER_COMMIT);
    const std::string deletedContents = readFileContents(aclFile.path);
    CHECK(deletedContents != committedContents);
    CHECK(deletedContents.find("9001") == std::string::npos);
    CHECK(lookup.find(9001U).peerDefault());
}

TEST_CASE("FNE REST talkgroup endpoints query, persist, and delete rules", "[fne][restapi][tg]")
{
    ScopedACLFile rulesFile;
    lookups::TalkgroupRulesLookup lookup(rulesFile.path, 0U, true, false);
    const std::string initialContents = readFileContents(rulesFile.path);
    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, nullptr, nullptr, &lookup);

    sendRequest(port, HTTP_PUT, FNE_PUT_TGID_ADD, talkgroupPayload(3100U, 1U, "REST TG"));
    CHECK(readFileContents(rulesFile.path) == initialContents);
    const lookups::TalkgroupRuleGroupVoice added = lookup.find(3100U, 1U);
    REQUIRE_FALSE(added.isInvalid());
    CHECK(added.name() == "REST TG");
    CHECK(added.config().active());

    json::object query = sendRequest(port, HTTP_GET, FNE_GET_TGID_QUERY);
    REQUIRE(query["tgs"].get<json::array>().size() == 1U);
    sendRequest(port, HTTP_GET, FNE_GET_TGID_COMMIT);
    const std::string committedContents = readFileContents(rulesFile.path);
    CHECK(committedContents != initialContents);
    CHECK(committedContents.find("3100") != std::string::npos);

    lookups::TalkgroupRulesLookup persisted(rulesFile.path, 0U, true, false);
    REQUIRE(persisted.read());
    CHECK_FALSE(persisted.find(3100U, 1U).isInvalid());

    json::object remove = json::object();
    remove["tgid"] = json::value((double)3100U);
    remove["slot"] = json::value((double)1U);
    sendRequest(port, HTTP_PUT, FNE_PUT_TGID_DELETE, remove);
    CHECK(readFileContents(rulesFile.path) == committedContents);
    sendRequest(port, HTTP_GET, FNE_GET_TGID_COMMIT);
    const std::string deletedContents = readFileContents(rulesFile.path);
    CHECK(deletedContents != committedContents);
    CHECK(deletedContents.find("3100") == std::string::npos);
    CHECK(lookup.find(3100U, 1U).isInvalid());
}

TEST_CASE("FNE REST adjacent-map endpoints query, persist, and delete entries", "[fne][restapi][adjmap]")
{
    ScopedACLFile mapFile;
    lookups::AdjSiteMapLookup lookup(mapFile.path, 0U);
    const std::string initialContents = readFileContents(mapFile.path);
    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, nullptr, nullptr, nullptr, nullptr, &lookup);

    json::object add = json::object();
    add["peerId"] = json::value((double)100U);
    json::array neighbors = json::array();
    neighbors.push_back(json::value((double)101U));
    neighbors.push_back(json::value((double)102U));
    add["neighbors"].set<json::array>(neighbors);
    sendRequest(port, HTTP_PUT, FNE_PUT_ADJ_MAP_ADD, add);
    CHECK(readFileContents(mapFile.path) == initialContents);

    CHECK(lookup.find(100U).neighbors() == std::vector<uint32_t> { 101U, 102U });
    json::object query = sendRequest(port, HTTP_GET, FNE_GET_ADJ_MAP_LIST);
    REQUIRE(query["peers"].get<json::array>().size() == 1U);
    sendRequest(port, HTTP_GET, FNE_GET_ADJ_MAP_COMMIT);
    const std::string committedContents = readFileContents(mapFile.path);
    CHECK(committedContents != initialContents);
    CHECK(committedContents.find("100") != std::string::npos);

    lookups::AdjSiteMapLookup persisted(mapFile.path, 0U);
    REQUIRE(persisted.read());
    CHECK(persisted.find(100U).neighbors() == std::vector<uint32_t> { 101U, 102U });

    json::object remove = json::object();
    remove["peerId"] = json::value((double)100U);
    sendRequest(port, HTTP_PUT, FNE_PUT_ADJ_MAP_DELETE, remove);
    CHECK(readFileContents(mapFile.path) == committedContents);
    sendRequest(port, HTTP_GET, FNE_GET_ADJ_MAP_COMMIT);
    const std::string deletedContents = readFileContents(mapFile.path);
    CHECK(deletedContents != committedContents);
    CHECK(deletedContents.find("100") == std::string::npos);
    CHECK(lookup.find(100U).neighbors().empty());
}

TEST_CASE("FNE REST reload endpoints refresh their configured lookup tables", "[fne][restapi][reload]")
{
    ScopedACLFile ridFile;
    ScopedACLFile peerFile;
    ScopedACLFile tgFile;
    lookups::RadioIdLookup rids(ridFile.path, 0U, true);
    lookups::PeerListLookup peers(peerFile.path, 0U, true, false);
    lookups::TalkgroupRulesLookup tgs(tgFile.path, 0U, true, false);

    rids.addEntry(1001U, true, "persisted RID");
    rids.commit(true);
    lookups::PeerId peer(2001U, "persisted peer", "secret", false);
    peers.addEntry(2001U, peer);
    peers.commit(true);

    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, &rids, nullptr, &tgs, &peers);
    sendRequest(port, HTTP_PUT, FNE_PUT_TGID_ADD, talkgroupPayload(3001U, 1U, "persisted TG"));
    sendRequest(port, HTTP_GET, FNE_GET_TGID_COMMIT);

    rids.addEntry(1002U, true, "memory only");
    peers.addEntry(2002U, lookups::PeerId(2002U, "memory only", "", false));
    sendRequest(port, HTTP_PUT, FNE_PUT_TGID_ADD, talkgroupPayload(3002U, 1U, "memory only"));

    sendRequest(port, HTTP_GET, FNE_GET_RELOAD_RIDS);
    sendRequest(port, HTTP_GET, FNE_GET_RELOAD_PEERLIST);
    sendRequest(port, HTTP_GET, FNE_GET_RELOAD_TGS);

    CHECK_FALSE(rids.find(1001U).radioDefault());
    CHECK(rids.find(1002U).radioDefault());
    CHECK_FALSE(peers.find(2001U).peerDefault());
    CHECK(peers.find(2002U).peerDefault());
    CHECK_FALSE(tgs.find(3001U, 1U).isInvalid());
    CHECK(tgs.find(3002U, 1U).isInvalid());
}

TEST_CASE("FNE REST omits the P25 roaming identity from the registration and affiliation reports when roaming is off", "[fne][restapi][roaming]")
{
    HostFNE host("fne-test.yml");
    lookups::RadioIdLookup radios("", 0U, true, false);
    lookups::TalkgroupRulesLookup talkgroups("", 0U, true, false);
    network::TrafficNetwork traffic(&host, "127.0.0.1", 62051U, 999999U, "test-password", "test-fne",
        false, false, false, false, true, true, true, true, true, 0U, false, true, true, true, 5U, 10U, 2U);
    traffic.setLookups(&radios, nullptr, &talkgroups, nullptr, nullptr, nullptr);

    FNETestHooks::addPeer(traffic, 3001U, network::NET_STAT_RUNNING, true);
    FNETestHooks::addGroupAffiliation(traffic, 3001U, 1001U, 4001U);

    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, &radios);
    server.api.setNetwork(&traffic);

    json::object regs = sendRequest(port, HTTP_GET, FNE_GET_UNIT_REG_LIST);
    CHECK(regs["units"].is<json::array>());
    CHECK_FALSE(regs["netId"].is<uint32_t>());
    CHECK_FALSE(regs["sysId"].is<uint32_t>());
    CHECK_FALSE(regs["suidUnits"].is<json::array>());

    json::object affs = sendRequest(port, HTTP_GET, FNE_GET_AFF_LIST);
    json::array peers = affs["affiliations"].get<json::array>();
    REQUIRE(peers.size() == 1U);
    json::array peerAffs = peers[0U].get<json::object>()["affiliations"].get<json::array>();
    REQUIRE(peerAffs.size() == 1U);
    json::object aff = peerAffs[0U].get<json::object>();
    CHECK(aff["srcId"].get<uint32_t>() == 1001U);
    CHECK_FALSE(aff["netId"].is<uint32_t>());
    CHECK_FALSE(aff["sysId"].is<uint32_t>());
}

TEST_CASE("FNE REST reports P25 roaming locations and served roamers and starts Forced queries", "[fne][restapi][roaming]")
{
    using namespace network::roaming;

    HostFNE host("fne-test.yml");
    lookups::RadioIdLookup radios("", 0U, true, false);
    lookups::TalkgroupRulesLookup talkgroups("", 0U, true, false);
    radios.addEntry(0x0F4240U, true, "home roamer");
    network::TrafficNetwork traffic(&host, "127.0.0.1", 62051U, 999999U, "test-password", "test-fne",
        false, false, false, false, true, true, true, true, true, 0U, false, true, true, true, 5U, 10U, 2U);
    traffic.setLookups(&radios, nullptr, &talkgroups, nullptr, nullptr, nullptr);

    network::RoamingConfig config;
    REQUIRE(config.set(0xDEE00U, 0x911U, ROAM_DEFAULT_EXPIRES));
    traffic.setP25RoamingConfig(config);

    auto deliver = [&](const network::RoamingLink& from, const RoamingMessage& msg) {
        uint8_t buffer[MSG_ROAM_MAX_LEN];
        const uint32_t length = RoamingCodec::encode(msg, buffer, sizeof(buffer));
        REQUIRE(length > 0U);
        // the service clock is wall-clock milliseconds in production; expiresIn is derived from it
        const uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        traffic.roaming()->process(from, msg.subFunc, buffer, length, now);
    };

    // home record: $DEE00.$911.0F4240 served by $DEE00.$13B RFSS 1 behind downstream FNE 2001
    const network::RoamingLink fne13B = { 2001U, false };
    traffic.roaming()->linkUp(fne13B, true, true, 0xDEE00U, 0x13BU);
    RoamingMessage reg;
    reg.subFunc = network::NET_SUBFUNC::ROAM_SERVING_REG;
    reg.txnId = 0x5001U;
    reg.suid = SUID{ 0xDEE00U, 0x911U, 0x0F4240U };
    reg.serving = RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U };
    reg.presence = RoamPresence::CONFIRMED;
    deliver(fne13B, reg);

    // served record: $DEE00.$222.5 registered at host 1001, home reached through FNE 2002 ($222)
    const network::RoamingLink host1001 = { 1001U, false };
    const network::RoamingLink fne222 = { 2002U, false };
    traffic.roaming()->linkUp(host1001, true, false, 0xDEE00U, 0x911U);
    traffic.roaming()->linkUp(fne222, true, true, 0xDEE00U, 0x222U);
    RoamingMessage visitor = reg;
    visitor.txnId = 0x5002U;
    visitor.suid = SUID{ 0xDEE00U, 0x222U, 5U };
    visitor.serving = RfssIdentity{ 0xDEE00U, 0x911U, 0x01U };
    deliver(host1001, visitor);
    RoamingMessage accepted;
    accepted.subFunc = network::NET_SUBFUNC::ROAM_SERVING_REG_RSP;
    accepted.txnId = 0x5002U;
    accepted.suid = visitor.suid;
    accepted.result = RoamResult::SUCCESS;
    accepted.expires = ROAM_DEFAULT_EXPIRES;
    accepted.access = RoamAccess::FULL;
    deliver(fne222, accepted);
    REQUIRE(traffic.roaming()->servingRecords().size() == 1U);

    // a foreign SU registered and affiliated behind peer 3001 (with one local affiliation there too)
    FNETestHooks::addGroupAffiliation(traffic, 3001U, 1001U, 4001U);
    FNETestHooks::addPeer(traffic, 3001U, network::NET_STAT_RUNNING, true);
    FNETestHooks::addSuidAffiliation(traffic, 3001U, SUID{ 0xDEE00U, 0x13BU, 7U }, 4002U);

    const uint16_t port = reserveLoopbackPort();
    ScopedRESTAPI server(port, &radios);
    server.api.setNetwork(&traffic);

    json::object locations = sendRequest(port, HTTP_GET, FNE_GET_P25_ROAMING_LOCATIONS);
    REQUIRE(locations["locations"].is<json::array>());
    json::array list = locations["locations"].get<json::array>();
    REQUIRE(list.size() == 1U);
    json::object location = list[0U].get<json::object>();
    CHECK(location["netId"].get<uint32_t>() == 0xDEE00U);
    CHECK(location["sysId"].get<uint32_t>() == 0x911U);
    CHECK(location["unitId"].get<uint32_t>() == 0x0F4240U);
    CHECK(location["servingNetId"].get<uint32_t>() == 0xDEE00U);
    CHECK(location["servingSysId"].get<uint32_t>() == 0x13BU);
    CHECK(location["servingRfssId"].get<uint32_t>() == 1U);
    CHECK(location["peerId"].get<uint32_t>() == 2001U);
    CHECK_FALSE(location["upstream"].get<bool>());
    CHECK(location["expiresIn"].get<uint32_t>() > 0U);

    json::object served = sendRequest(port, HTTP_GET, FNE_GET_P25_ROAMING_SERVED);
    REQUIRE(served["served"].is<json::array>());
    list = served["served"].get<json::array>();
    REQUIRE(list.size() == 1U);
    json::object roamer = list[0U].get<json::object>();
    CHECK(roamer["sysId"].get<uint32_t>() == 0x222U);
    CHECK(roamer["unitId"].get<uint32_t>() == 5U);
    CHECK(roamer["peerId"].get<uint32_t>() == 1001U);

    json::object regs = sendRequest(port, HTTP_GET, FNE_GET_UNIT_REG_LIST);
    CHECK(regs["netId"].get<uint32_t>() == 0xDEE00U);
    CHECK(regs["sysId"].get<uint32_t>() == 0x911U);
    REQUIRE(regs["suidUnits"].is<json::array>());
    json::array suidUnits = regs["suidUnits"].get<json::array>();
    REQUIRE(suidUnits.size() == 1U);
    CHECK(suidUnits[0U].get<json::object>()["unitId"].get<uint32_t>() == 7U);
    CHECK(suidUnits[0U].get<json::object>()["sysId"].get<uint32_t>() == 0x13BU);

    json::object affs = sendRequest(port, HTTP_GET, FNE_GET_AFF_LIST);
    REQUIRE(affs["affiliations"].is<json::array>());
    json::array peers = affs["affiliations"].get<json::array>();
    REQUIRE(peers.size() == 1U);
    json::array peerAffs = peers[0U].get<json::object>()["affiliations"].get<json::array>();
    REQUIRE(peerAffs.size() == 2U);
    bool sawLocal = false;
    bool sawForeign = false;
    for (json::value& value : peerAffs) {
        json::object aff = value.get<json::object>();
        if (aff["srcId"].get<uint32_t>() == 1001U) {
            sawLocal = true;
            CHECK(aff["sysId"].get<uint32_t>() == 0x911U);
        }
        if (aff["srcId"].get<uint32_t>() == 7U) {
            sawForeign = true;
            CHECK(aff["dstId"].get<uint32_t>() == 4002U);
            CHECK(aff["sysId"].get<uint32_t>() == 0x13BU);
        }
    }
    CHECK(sawLocal);
    CHECK(sawForeign);

    // a valid Forced query is actually issued: a pending transaction toward the serving link is created
    const size_t pendingBefore = traffic.roaming()->pendingCount();
    uint32_t queryNetId = 0xDEE00U;
    uint32_t querySysId = 0x911U;
    uint32_t queryUnitId = 0x0F4240U;
    json::object query = json::object();
    query["netId"].set<uint32_t>(queryNetId);
    query["sysId"].set<uint32_t>(querySysId);
    query["unitId"].set<uint32_t>(queryUnitId);
    sendRequest(port, HTTP_PUT, FNE_PUT_P25_ROAMING_QUERY, query);
    CHECK(traffic.roaming()->pendingCount() == pendingBefore + 1U);

    // validation failures are rejected with 400 and a specific message, and issue nothing
    const std::string token = authenticateRaw(port);
    const size_t pendingAfter = traffic.roaming()->pendingCount();
    const std::string numberMessage = "netId, sysId and unitId must be valid integers";
    const std::string rangeMessage = "netId, sysId or unitId out of range";
    auto expectRejected = [&](const std::string& body, const std::string& message) {
        INFO(body);
        RawResponse rsp = sendRaw(port, HTTP_PUT, FNE_PUT_P25_ROAMING_QUERY, token, body);
        // the FNE REST contract reports errors in the JSON status/message (the HTTP envelope stays 200)
        CHECK(rsp.body["status"].get<int>() == 400);
        CHECK(rsp.body["message"].get<std::string>() == message);
    };

    {
        // malformed JSON is rejected by the shared body parser before any field is read
        INFO("malformed body");
        RawResponse rsp = sendRaw(port, HTTP_PUT, FNE_PUT_P25_ROAMING_QUERY, token, "{\"netId\": ");
        CHECK(rsp.body["status"].get<int>() == 400);
        CHECK_FALSE(rsp.body["message"].get<std::string>().empty());
    }

    expectRejected("[1,2,3]", "Request was not a valid JSON object.");
    expectRejected("{\"sysId\":2321,\"unitId\":1000000}", numberMessage);
    expectRejected("{\"netId\":912896,\"unitId\":1000000}", numberMessage);
    expectRejected("{\"netId\":912896,\"sysId\":2321}", numberMessage);
    expectRejected("{\"netId\":\"912896\",\"sysId\":2321,\"unitId\":1000000}", numberMessage);
    expectRejected("{\"netId\":912896,\"sysId\":true,\"unitId\":1000000}", numberMessage);
    expectRejected("{\"netId\":912896,\"sysId\":2321,\"unitId\":-1}", numberMessage);
    expectRejected("{\"netId\":912896,\"sysId\":2321,\"unitId\":1.5}", numberMessage);
    // 4294967296 + 0xDEE00 would wrap to a valid WACN if cast without a range check
    expectRejected("{\"netId\":4295880192,\"sysId\":2321,\"unitId\":1000000}", numberMessage);
    expectRejected("{\"netId\":1048576,\"sysId\":2321,\"unitId\":1000000}", rangeMessage);
    expectRejected("{\"netId\":912896,\"sysId\":4096,\"unitId\":1000000}", rangeMessage);
    expectRejected("{\"netId\":912896,\"sysId\":2321,\"unitId\":16777216}", rangeMessage);

    // no home location record for this SUID
    expectRejected("{\"netId\":912896,\"sysId\":2321,\"unitId\":99}", "SUID has no home location record");
    CHECK(traffic.roaming()->pendingCount() == pendingAfter);
}
