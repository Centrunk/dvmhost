// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "common/Defines.h"
#include "common/network/P25Roaming.h"
#include "common/network/RTPFNEHeader.h"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <vector>

using namespace network;
using namespace network::roaming;

TEST_CASE("P25 roaming identity helpers", "[network][roaming][suid]")
{
    SECTION("Opcodes_Use_Previously_Unused_Codes") {
        CHECK(static_cast<uint8_t>(NET_FUNC::ROAMING) == 0x94U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID) == 0x04U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_DEREG_SUID) == 0x05U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ANNC_SUBFUNC_GRP_AFFIL_SUID) == 0x06U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ANNC_SUBFUNC_GRP_UNAFFIL_SUID) == 0x07U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID) == 0x92U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ANNC_SUBFUNC_AFFILS_SUID) == 0x93U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_SERVING_REG) == 0x00U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_SERVING_REG_RSP) == 0x01U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_SERVING_DEREG) == 0x02U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_SERVING_DEREG_RSP) == 0x03U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_HOME_DEREG) == 0x04U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_HOME_DEREG_RSP) == 0x05U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_QUERY) == 0x06U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_QUERY_RSP) == 0x07U);
        CHECK(static_cast<uint8_t>(NET_SUBFUNC::ROAM_GEN_RSP) == 0x7FU);
    }

    SECTION("Result_And_Field_Values_Match_The_Spec") {
        CHECK(RoamResult::SUCCESS == 0x00U);
        CHECK(RoamResult::MME_SU_REG_DISALLOWED == 0x18U);
        CHECK(RoamResult::MME_MUST_CONFIRM_SU_PRESENCE == 0x1BU);
        CHECK(RoamResult::GEN_PROC_UNSUPPORTED == 0x1CU);
        CHECK(RoamResult::MME_SU_UNKNOWN == 0x22U);
        CHECK(RoamResult::MME_SU_AUTHEN_REQUIRED == 0x2FU);
        CHECK(RoamResult::MME_OBJ_NOT_REG_AT_SERV == 0x57U);
        CHECK(RoamAccess::EMERGENCY_ONLY == 2U);
        CHECK(RoamQueryType::SERVING == 3U);
        CHECK(ROAM_FLAG_RADIO_INHIBITED == 0x80U);
        CHECK(ROAM_DEFAULT_HOP_COUNT == 8U);
        CHECK(ROAM_DEFAULT_EXPIRES == 18000U);
        CHECK(ROAM_MIN_EXPIRES == 14400U);
        CHECK(ROAM_DEFAULT_HOME_TIMEOUT_MS == 5000U);
        CHECK(ROAM_RETRY_TIME_MS == 10000U);
        CHECK(ROAM_REFRESH_PERCENT == 80U);
    }

    SECTION("SUID_Packs_As_WACN_SysID_UnitID") {
        const SUID suid = { 0xDEE00U, 0x911U, 0x0F4240U };
        CHECK(suid.pack() == 0x00DEE009110F4240ULL);

        const SUID max = { 0xFFFFFU, 0xFFFU, 0xFFFFFFU };
        CHECK(max.pack() == 0x00FFFFFFFFFFFFFFULL);

        const SUID zero = { 0U, 0U, 0U };
        CHECK(zero.pack() == 0ULL);

        const SUID unpacked = SUID::unpack(0x00DEE009110F4240ULL);
        CHECK(unpacked.netId == 0xDEE00U);
        CHECK(unpacked.sysId == 0x911U);
        CHECK(unpacked.unitId == 0x0F4240U);
        CHECK(unpacked == suid);
    }

    SECTION("Ranges_Are_Validated") {
        CHECK(SUID::validSystem(0U, 0U));
        CHECK(SUID::validSystem(0xFFFFFU, 0xFFFU));
        CHECK_FALSE(SUID::validSystem(0x100000U, 0x001U));
        CHECK_FALSE(SUID::validSystem(0x00001U, 0x1000U));

        CHECK(SUID{ 0xDEE00U, 0x911U, 0xFFFFFFU }.valid());
        CHECK_FALSE(SUID{ 0xDEE00U, 0x911U, 0x1000000U }.valid());
        CHECK_FALSE(SUID{ 0x100000U, 0x911U, 1U }.valid());

        CHECK(SUID::systemKey(0xDEE00U, 0x911U) == 0xDEE00911U);

        const RfssIdentity rfss = { 0xDEE00U, 0x13BU, 0x01U };
        CHECK(rfss.valid());
        CHECK(rfss == RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U });
        CHECK_FALSE(rfss == RfssIdentity{ 0xDEE00U, 0x13BU, 0x02U });
        CHECK_FALSE(RfssIdentity{ 0xDEE00U, 0x1000U, 0x01U }.valid());
    }
}

namespace {
    /**
     * @brief Builds a ROAMING message with the shared test header, SUID and serving RFSS.
     * @param subFunc ROAMING sub-function.
     * @returns RoamingMessage Message with test values.
     */
    RoamingMessage baseMessage(uint8_t subFunc)
    {
        RoamingMessage msg;
        msg.subFunc = subFunc;
        msg.version = ROAM_VERSION;
        msg.hopCount = 8U;
        msg.txnId = 0x12345678U;
        msg.suid = SUID{ 0xDEE00U, 0x911U, 0x0F4240U };
        msg.serving = RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U };
        return msg;
    }

    /**
     * @brief Encodes a ROAMING message.
     * @param msg Message to encode.
     * @returns std::vector<uint8_t> Encoded bytes (empty when the codec refused the message).
     */
    std::vector<uint8_t> encodeMessage(const RoamingMessage& msg)
    {
        uint8_t buffer[MSG_ROAM_MAX_LEN];
        ::memset(buffer, 0xA5U, sizeof(buffer));
        const uint32_t length = RoamingCodec::encode(msg, buffer, sizeof(buffer));
        return std::vector<uint8_t>(buffer, buffer + length);
    }

    /**
     * @brief Concatenates byte groups.
     * @param groups Byte groups.
     * @returns std::vector<uint8_t> Concatenated bytes.
     */
    std::vector<uint8_t> bytes(std::initializer_list<std::vector<uint8_t>> groups)
    {
        std::vector<uint8_t> out;
        for (const auto& group : groups) {
            out.insert(out.end(), group.begin(), group.end());
        }
        return out;
    }

    const std::vector<uint8_t> HDR = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U };
    const std::vector<uint8_t> SUID_BYTES = { 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U, 0x0FU, 0x42U, 0x40U };
    const std::vector<uint8_t> RFSS_BYTES = { 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x01U };
} // namespace

TEST_CASE("P25 roaming message codec", "[network][roaming][codec]")
{
    SECTION("Message_Lengths_Match_The_Spec_Table") {
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_SERVING_REG) == 21U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_SERVING_REG_RSP) == 21U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_SERVING_DEREG) == 20U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_SERVING_DEREG_RSP) == 15U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_HOME_DEREG) == 15U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_HOME_DEREG_RSP) == 15U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_QUERY) == 15U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_QUERY_RSP) == 16U);
        CHECK(RoamingCodec::messageLength(NET_SUBFUNC::ROAM_GEN_RSP) == 8U);
        CHECK(RoamingCodec::messageLength(0x10U) == 0U);

        CHECK(RoamingCodec::isRequest(NET_SUBFUNC::ROAM_SERVING_REG));
        CHECK(RoamingCodec::isRequest(NET_SUBFUNC::ROAM_QUERY));
        CHECK(RoamingCodec::isRequest(0x10U));
        CHECK_FALSE(RoamingCodec::isRequest(NET_SUBFUNC::ROAM_SERVING_REG_RSP));
        CHECK_FALSE(RoamingCodec::isRequest(NET_SUBFUNC::ROAM_GEN_RSP));
        CHECK_FALSE(RoamingCodec::isRequest(0x11U));
    }

    SECTION("Known_Answer_Vectors") {
        RoamingMessage msg = baseMessage(NET_SUBFUNC::ROAM_SERVING_REG);
        msg.presence = RoamPresence::CONFIRMED;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, RFSS_BYTES, { 0x01U } }));

        msg = baseMessage(NET_SUBFUNC::ROAM_SERVING_REG_RSP);
        msg.result = RoamResult::SUCCESS;
        msg.expires = 18000U;
        msg.access = RoamAccess::FULL;
        msg.flags = 0x00U;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, { 0x00U, 0x00U, 0x00U, 0x46U, 0x50U, 0x01U, 0x00U } }));

        msg.flags = ROAM_FLAG_RADIO_INHIBITED;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, { 0x00U, 0x00U, 0x00U, 0x46U, 0x50U, 0x01U, 0x80U } }));

        msg = baseMessage(NET_SUBFUNC::ROAM_SERVING_DEREG);
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, RFSS_BYTES }));

        msg = baseMessage(NET_SUBFUNC::ROAM_SERVING_DEREG_RSP);
        msg.result = RoamResult::MME_OBJ_NOT_REG_AT_SERV;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, { 0x57U } }));

        msg = baseMessage(NET_SUBFUNC::ROAM_HOME_DEREG);
        msg.qualifier = RoamQualifier::NON_ROAMED;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, { 0x01U } }));

        msg = baseMessage(NET_SUBFUNC::ROAM_HOME_DEREG_RSP);
        msg.result = RoamResult::MME_SU_UNKNOWN;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, { 0x22U } }));

        msg = baseMessage(NET_SUBFUNC::ROAM_QUERY);
        msg.queryType = RoamQueryType::FORCED;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, { 0x01U } }));

        msg = baseMessage(NET_SUBFUNC::ROAM_QUERY_RSP);
        msg.result = RoamResult::SUCCESS;
        msg.interested = 1U;
        CHECK(encodeMessage(msg) == bytes({ HDR, SUID_BYTES, { 0x00U, 0x01U } }));

        msg = baseMessage(NET_SUBFUNC::ROAM_GEN_RSP);
        msg.rejectedSubFunc = 0x10U;
        msg.result = RoamResult::GEN_PROC_UNSUPPORTED;
        CHECK(encodeMessage(msg) == std::vector<uint8_t>({ 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x10U, 0x1CU }));
    }

    SECTION("Decode_Reads_The_Known_Answer_Vectors") {
        const std::vector<uint8_t> reg = bytes({ HDR, SUID_BYTES, RFSS_BYTES, { 0x01U } });
        RoamingMessage msg;
        REQUIRE(RoamingCodec::decode(NET_SUBFUNC::ROAM_SERVING_REG, reg.data(), (uint32_t)reg.size(), msg) == RoamDecode::OK);
        CHECK(msg.subFunc == NET_SUBFUNC::ROAM_SERVING_REG);
        CHECK(msg.version == 1U);
        CHECK(msg.hopCount == 8U);
        CHECK(msg.txnId == 0x12345678U);
        CHECK(msg.suid == SUID{ 0xDEE00U, 0x911U, 0x0F4240U });
        CHECK(msg.serving == RfssIdentity{ 0xDEE00U, 0x13BU, 0x01U });
        CHECK(msg.presence == RoamPresence::CONFIRMED);

        const std::vector<uint8_t> rsp = bytes({ HDR, SUID_BYTES, { 0x00U, 0x00U, 0x00U, 0x46U, 0x50U, 0x02U, 0x80U } });
        REQUIRE(RoamingCodec::decode(NET_SUBFUNC::ROAM_SERVING_REG_RSP, rsp.data(), (uint32_t)rsp.size(), msg) == RoamDecode::OK);
        CHECK(msg.result == RoamResult::SUCCESS);
        CHECK(msg.expires == 18000U);
        CHECK(msg.access == RoamAccess::EMERGENCY_ONLY);
        CHECK(msg.flags == ROAM_FLAG_RADIO_INHIBITED);

        const std::vector<uint8_t> qrsp = bytes({ HDR, SUID_BYTES, { 0x22U, 0x00U } });
        REQUIRE(RoamingCodec::decode(NET_SUBFUNC::ROAM_QUERY_RSP, qrsp.data(), (uint32_t)qrsp.size(), msg) == RoamDecode::OK);
        CHECK(msg.result == RoamResult::MME_SU_UNKNOWN);
        CHECK(msg.interested == 0U);

        const std::vector<uint8_t> gen = { 0x01U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U, 0x10U, 0x1CU };
        REQUIRE(RoamingCodec::decode(NET_SUBFUNC::ROAM_GEN_RSP, gen.data(), (uint32_t)gen.size(), msg) == RoamDecode::OK);
        CHECK(msg.rejectedSubFunc == 0x10U);
        CHECK(msg.result == RoamResult::GEN_PROC_UNSUPPORTED);
    }

    SECTION("Serving_Registration_Response_Rejects_Undefined_Access_And_Flags") {
        // access is 0 none / 1 full / 2 emergency only; only flags bit 7 (radio inhibited) is defined
        RoamingMessage msg;
        for (uint8_t access : { 0x00U, 0x01U, 0x02U }) {
            INFO("access " << (uint32_t)access);
            const std::vector<uint8_t> ok = bytes({ HDR, SUID_BYTES, { 0x00U, 0x00U, 0x00U, 0x46U, 0x50U, access, 0x80U } });
            CHECK(RoamingCodec::decode(NET_SUBFUNC::ROAM_SERVING_REG_RSP, ok.data(), (uint32_t)ok.size(), msg) == RoamDecode::OK);
        }

        for (uint8_t access : { 0x03U, 0x7FU, 0xFFU }) {
            INFO("access " << (uint32_t)access);
            const std::vector<uint8_t> bad = bytes({ HDR, SUID_BYTES, { 0x00U, 0x00U, 0x00U, 0x46U, 0x50U, access, 0x00U } });
            CHECK(RoamingCodec::decode(NET_SUBFUNC::ROAM_SERVING_REG_RSP, bad.data(), (uint32_t)bad.size(), msg) == RoamDecode::OUT_OF_RANGE);
        }

        for (uint8_t flags : { 0x01U, 0x40U, 0x7FU, 0x81U, 0xFFU }) {
            INFO("flags " << (uint32_t)flags);
            const std::vector<uint8_t> bad = bytes({ HDR, SUID_BYTES, { 0x00U, 0x00U, 0x00U, 0x46U, 0x50U, 0x01U, flags } });
            CHECK(RoamingCodec::decode(NET_SUBFUNC::ROAM_SERVING_REG_RSP, bad.data(), (uint32_t)bad.size(), msg) == RoamDecode::OUT_OF_RANGE);
        }
    }

    SECTION("Truncation_And_Overlength_Are_Malformed_For_Every_Subfunction") {
        const uint8_t subFuncs[9U] = { NET_SUBFUNC::ROAM_SERVING_REG, NET_SUBFUNC::ROAM_SERVING_REG_RSP,
            NET_SUBFUNC::ROAM_SERVING_DEREG, NET_SUBFUNC::ROAM_SERVING_DEREG_RSP, NET_SUBFUNC::ROAM_HOME_DEREG,
            NET_SUBFUNC::ROAM_HOME_DEREG_RSP, NET_SUBFUNC::ROAM_QUERY, NET_SUBFUNC::ROAM_QUERY_RSP, NET_SUBFUNC::ROAM_GEN_RSP };
        uint8_t buffer[MSG_ROAM_MAX_LEN + 1U];
        for (uint8_t subFunc : subFuncs) {
            RoamingMessage msg = baseMessage(subFunc);
            const uint32_t length = RoamingCodec::encode(msg, buffer, sizeof(buffer));
            REQUIRE(length == RoamingCodec::messageLength(subFunc));
            buffer[length] = 0x00U;

            RoamingMessage untouched;
            untouched.txnId = 0xCAFEF00DU;
            for (uint32_t len = 0U; len < length; len++) {
                INFO("subFunc " << (uint32_t)subFunc << " length " << len);
                CHECK(RoamingCodec::decode(subFunc, buffer, len, untouched) == RoamDecode::MALFORMED_LENGTH);
            }
            CHECK(RoamingCodec::decode(subFunc, buffer, length + 1U, untouched) == RoamDecode::MALFORMED_LENGTH);
            CHECK(untouched.txnId == 0xCAFEF00DU);
            CHECK(RoamingCodec::decode(subFunc, nullptr, length, untouched) == RoamDecode::MALFORMED_LENGTH);

            // a short output buffer is refused rather than overrun
            CHECK(RoamingCodec::encode(msg, buffer, length - 1U) == 0U);
        }
    }

    SECTION("Zero_Maximum_And_One_Past_Maximum_Identity_Values") {
        RoamingMessage msg = baseMessage(NET_SUBFUNC::ROAM_HOME_DEREG);
        msg.suid = SUID{ 0U, 0U, 0U };
        CHECK(encodeMessage(msg) == bytes({ HDR, { 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U }, { 0x00U } }));

        msg.suid = SUID{ 0xFFFFFU, 0xFFFU, 0xFFFFFFU };
        const std::vector<uint8_t> max = encodeMessage(msg);
        CHECK(max == bytes({ HDR, { 0x0FU, 0xFFU, 0xFFU, 0x0FU, 0xFFU, 0xFFU, 0xFFU, 0xFFU }, { 0x00U } }));
        RoamingMessage decoded;
        REQUIRE(RoamingCodec::decode(NET_SUBFUNC::ROAM_HOME_DEREG, max.data(), (uint32_t)max.size(), decoded) == RoamDecode::OK);
        CHECK(decoded.suid == SUID{ 0xFFFFFU, 0xFFFU, 0xFFFFFFU });

        msg.suid = SUID{ 0x100000U, 0x001U, 1U };
        CHECK(encodeMessage(msg).empty());
        msg.suid = SUID{ 0x00001U, 0x1000U, 1U };
        CHECK(encodeMessage(msg).empty());
        msg.suid = SUID{ 0x00001U, 0x001U, 0x1000000U };
        CHECK(encodeMessage(msg).empty());

        msg = baseMessage(NET_SUBFUNC::ROAM_SERVING_DEREG);
        msg.serving = RfssIdentity{ 0x100000U, 0x13BU, 1U };
        CHECK(encodeMessage(msg).empty());

        std::vector<uint8_t> wacn = bytes({ HDR, { 0x10U, 0x00U, 0x00U, 0x09U, 0x11U, 0x0FU, 0x42U, 0x40U }, { 0x00U } });
        CHECK(RoamingCodec::decode(NET_SUBFUNC::ROAM_HOME_DEREG, wacn.data(), (uint32_t)wacn.size(), decoded) == RoamDecode::OUT_OF_RANGE);
        std::vector<uint8_t> sys = bytes({ HDR, { 0x0DU, 0xEEU, 0x00U, 0x10U, 0x00U, 0x0FU, 0x42U, 0x40U }, { 0x00U } });
        CHECK(RoamingCodec::decode(NET_SUBFUNC::ROAM_HOME_DEREG, sys.data(), (uint32_t)sys.size(), decoded) == RoamDecode::OUT_OF_RANGE);
        std::vector<uint8_t> rfss = bytes({ HDR, SUID_BYTES, { 0x0DU, 0xEEU, 0x00U, 0x10U, 0x00U, 0x01U } });
        CHECK(RoamingCodec::decode(NET_SUBFUNC::ROAM_SERVING_DEREG, rfss.data(), (uint32_t)rfss.size(), decoded) == RoamDecode::OUT_OF_RANGE);
    }

    SECTION("Version_And_Unknown_Subfunction") {
        std::vector<uint8_t> v2 = bytes({ { 0x02U, 0x08U, 0x12U, 0x34U, 0x56U, 0x78U }, SUID_BYTES, { 0x00U } });
        RoamingMessage msg;
        CHECK(RoamingCodec::decode(NET_SUBFUNC::ROAM_HOME_DEREG, v2.data(), (uint32_t)v2.size(), msg) == RoamDecode::BAD_VERSION);
        CHECK(RoamingCodec::decode(0x10U, v2.data(), (uint32_t)v2.size(), msg) == RoamDecode::UNKNOWN_SUBFUNC);

        uint8_t version = 0U;
        uint8_t hopCount = 0U;
        uint32_t txnId = 0U;
        CHECK(RoamingCodec::decodeHeader(HDR.data(), (uint32_t)HDR.size(), version, hopCount, txnId) == RoamDecode::OK);
        CHECK(version == 1U);
        CHECK(hopCount == 8U);
        CHECK(txnId == 0x12345678U);
        CHECK(RoamingCodec::decodeHeader(HDR.data(), 5U, version, hopCount, txnId) == RoamDecode::MALFORMED_LENGTH);
    }
}

TEST_CASE("P25 roaming announcement, login and grant codecs", "[network][roaming][codec]")
{
    const SUID suid = { 0xDEE00U, 0x911U, 0x0F4240U };
    const std::vector<uint8_t> unitBytes = { 0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };
    const std::vector<uint8_t> affilBytes = { 0x0FU, 0x42U, 0x40U, 0x00U, 0x0FU, 0xA1U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };

    SECTION("Single_Announcements_Known_Bytes") {
        uint8_t buffer[MSG_ANNC_GRP_AFFIL_SUID_LEN];
        SuidAnnouncement entry;
        entry.suid = suid;
        entry.talkgroup = 4001U;

        const uint8_t unitForms[3U] = { NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, NET_SUBFUNC::ANNC_SUBFUNC_UNIT_DEREG_SUID,
            NET_SUBFUNC::ANNC_SUBFUNC_GRP_UNAFFIL_SUID };
        for (uint8_t subFunc : unitForms) {
            INFO("subFunc " << (uint32_t)subFunc);
            REQUIRE(RoamingCodec::encodeSuidAnnouncement(subFunc, entry, buffer, sizeof(buffer)) == 8U);
            CHECK(std::vector<uint8_t>(buffer, buffer + 8U) == unitBytes);

            SuidAnnouncement decoded;
            REQUIRE(RoamingCodec::decodeSuidAnnouncement(subFunc, unitBytes.data(), 8U, decoded));
            CHECK(decoded.suid == suid);
            CHECK(decoded.talkgroup == 0U);
            for (uint32_t len = 0U; len < 8U; len++) {
                CHECK_FALSE(RoamingCodec::decodeSuidAnnouncement(subFunc, unitBytes.data(), len, decoded));
            }
            const std::vector<uint8_t> longer = bytes({ unitBytes, { 0x00U } });
            CHECK_FALSE(RoamingCodec::decodeSuidAnnouncement(subFunc, longer.data(), 9U, decoded));
        }

        REQUIRE(RoamingCodec::encodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_GRP_AFFIL_SUID, entry, buffer, sizeof(buffer)) == 11U);
        CHECK(std::vector<uint8_t>(buffer, buffer + 11U) == affilBytes);
        SuidAnnouncement decoded;
        REQUIRE(RoamingCodec::decodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_GRP_AFFIL_SUID, affilBytes.data(), 11U, decoded));
        CHECK(decoded.suid == suid);
        CHECK(decoded.talkgroup == 4001U);
        for (uint32_t len = 0U; len < 11U; len++) {
            CHECK_FALSE(RoamingCodec::decodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_GRP_AFFIL_SUID, affilBytes.data(), len, decoded));
        }

        // a non-SUID announcement sub-function is not a SUID form
        CHECK(RoamingCodec::announcementLength(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG) == 0U);
        CHECK(RoamingCodec::encodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, entry, buffer, sizeof(buffer)) == 0U);
    }

    SECTION("Single_Announcement_Ranges") {
        uint8_t buffer[MSG_ANNC_GRP_AFFIL_SUID_LEN];
        SuidAnnouncement entry;
        entry.suid = SUID{ 0x100000U, 0x911U, 1U };
        CHECK(RoamingCodec::encodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, entry, buffer, sizeof(buffer)) == 0U);
        entry.suid = suid;
        entry.talkgroup = 0x1000000U;
        CHECK(RoamingCodec::encodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_GRP_AFFIL_SUID, entry, buffer, sizeof(buffer)) == 0U);

        const std::vector<uint8_t> badWacn = { 0x0FU, 0x42U, 0x40U, 0x10U, 0x00U, 0x00U, 0x09U, 0x11U };
        SuidAnnouncement decoded;
        CHECK_FALSE(RoamingCodec::decodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, badWacn.data(), 8U, decoded));
        const std::vector<uint8_t> badSys = { 0x0FU, 0x42U, 0x40U, 0x0DU, 0xEEU, 0x00U, 0x10U, 0x00U };
        CHECK_FALSE(RoamingCodec::decodeSuidAnnouncement(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, badSys.data(), 8U, decoded));
    }

    SECTION("Bulk_Announcements_Known_Bytes_And_Count_Checks") {
        std::vector<SuidAnnouncement> regs(2U);
        regs[0U].suid = suid;
        regs[1U].suid = SUID{ 0xDEE00U, 0x911U, 0x000001U };
        const std::vector<uint8_t> regBytes = RoamingCodec::encodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, regs);
        CHECK(regBytes == bytes({ { 0x00U, 0x00U, 0x00U, 0x02U }, unitBytes,
            { 0x00U, 0x00U, 0x01U, 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U } }));

        std::vector<SuidAnnouncement> affs(1U);
        affs[0U].suid = suid;
        affs[0U].talkgroup = 4001U;
        const std::vector<uint8_t> affBytes = RoamingCodec::encodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_AFFILS_SUID, affs);
        CHECK(affBytes == bytes({ { 0x00U, 0x00U, 0x00U, 0x01U }, affilBytes }));

        CHECK(RoamingCodec::encodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, std::vector<SuidAnnouncement>()) ==
            std::vector<uint8_t>({ 0x00U, 0x00U, 0x00U, 0x00U }));

        std::vector<SuidAnnouncement> decoded;
        REQUIRE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, regBytes.data(), (uint32_t)regBytes.size(), decoded));
        REQUIRE(decoded.size() == 2U);
        CHECK(decoded[1U].suid.unitId == 1U);
        REQUIRE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_AFFILS_SUID, affBytes.data(), (uint32_t)affBytes.size(), decoded));
        REQUIRE(decoded.size() == 1U);
        CHECK(decoded[0U].talkgroup == 4001U);

        // count overflow, count/length mismatch, truncated count and a bad entry are rejected without output
        decoded.assign(3U, SuidAnnouncement());
        const std::vector<uint8_t> overflow = bytes({ { 0xFFU, 0xFFU, 0xFFU, 0xFFU }, unitBytes });
        CHECK_FALSE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, overflow.data(), (uint32_t)overflow.size(), decoded));
        const std::vector<uint8_t> shortBy = bytes({ { 0x00U, 0x00U, 0x00U, 0x02U }, unitBytes });
        CHECK_FALSE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, shortBy.data(), (uint32_t)shortBy.size(), decoded));
        const std::vector<uint8_t> trailing = bytes({ { 0x00U, 0x00U, 0x00U, 0x01U }, unitBytes, { 0x00U } });
        CHECK_FALSE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, trailing.data(), (uint32_t)trailing.size(), decoded));
        CHECK_FALSE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, overflow.data(), 3U, decoded));
        const std::vector<uint8_t> badEntry = bytes({ { 0x00U, 0x00U, 0x00U, 0x01U }, { 0x0FU, 0x42U, 0x40U, 0x10U, 0x00U, 0x00U, 0x09U, 0x11U } });
        CHECK_FALSE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID, badEntry.data(), (uint32_t)badEntry.size(), decoded));
        CHECK(decoded.size() == 3U);
        CHECK_FALSE(RoamingCodec::decodeSuidBulk(NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID, regBytes.data(), (uint32_t)regBytes.size(), decoded));
    }

    SECTION("RPTC_JSON_Object") {
        json::value v;
        REQUIRE(json::parse(v, std::string("{\"p25Roaming\": { \"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 1 }}")).empty());
        RoamingPeerConfig peer;
        REQUIRE(RoamingCodec::parseConfig(v.get<json::object>(), peer));
        CHECK(peer.netId == 0xDEE00U);
        CHECK(peer.sysId == 0x13BU);
        CHECK(peer.rfssId == 0x01U);

        json::object roam = RoamingCodec::buildConfig(0xDEE00U, 0x13BU, 0x01U);
        CHECK(roam["version"].get<uint32_t>() == 1U);
        CHECK(roam["netId"].get<uint32_t>() == 912896U);
        CHECK(roam["sysId"].get<uint32_t>() == 315U);
        CHECK(roam["rfssId"].get<uint32_t>() == 1U);

        json::object config = json::object();
        config["p25Roaming"].set<json::object>(roam);
        RoamingPeerConfig built;
        REQUIRE(RoamingCodec::parseConfig(config, built));
        CHECK(built.netId == 0xDEE00U);

        const char* rejected[5U] = {
            "{\"identity\": \"no roaming\"}",
            "{\"p25Roaming\": { \"version\": 2, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 1048576, \"sysId\": 315, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 912896, \"sysId\": 0, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": \"DEE00\", \"sysId\": 315 }}"
        };
        for (const char* text : rejected) {
            INFO(text);
            json::value r;
            REQUIRE(json::parse(r, std::string(text)).empty());
            RoamingPeerConfig out;
            CHECK_FALSE(RoamingCodec::parseConfig(r.get<json::object>(), out));
        }
    }

    SECTION("RPTC_JSON_Untrusted_Numbers") {
        const char* bad[9U] = {
            "{\"p25Roaming\": { \"version\": 1, \"netId\": -1, \"sysId\": 315, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 912896.5, \"sysId\": 315, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 4295880192, \"sysId\": 315, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 1e20, \"sysId\": 315, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1.5, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 912896, \"sysId\": 4294967297, \"rfssId\": 1 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 1.9 }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": \"1\" }}",
            "{\"p25Roaming\": { \"version\": 1, \"netId\": 912896, \"sysId\": 315, \"rfssId\": 256 }}"
        };
        for (const char* text : bad) {
            INFO(text);
            json::value r;
            REQUIRE(json::parse(r, std::string(text)).empty());
            RoamingPeerConfig out;
            out.netId = 7U;
            out.sysId = 8U;
            out.rfssId = 9U;
            CHECK_FALSE(RoamingCodec::parseConfig(r.get<json::object>(), out));
            CHECK(out.netId == 7U);
            CHECK(out.sysId == 8U);
            CHECK(out.rfssId == 9U);
        }

        // an absent rfssId is a downstream FNE (0)
        json::value ok;
        REQUIRE(json::parse(ok, std::string("{\"p25Roaming\": { \"version\": 1, \"netId\": 912896, \"sysId\": 315 }}")).empty());
        RoamingPeerConfig peer;
        peer.rfssId = 9U;
        REQUIRE(RoamingCodec::parseConfig(ok.get<json::object>(), peer));
        CHECK(peer.rfssId == 0U);
    }

    SECTION("RPTC_ACK_Payload") {
        uint8_t payload[CONFIG_ACK_ROAMING_LEN];
        REQUIRE(RoamingCodec::encodeConfigAck(payload, sizeof(payload), true, 0xDEE00U, 0x13BU) == 6U);
        CHECK(std::vector<uint8_t>(payload, payload + 6U) == std::vector<uint8_t>({ 0xC0U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU }));
        REQUIRE(RoamingCodec::encodeConfigAck(payload, sizeof(payload), false, 0xDEE00U, 0x13BU) == 1U);
        CHECK(payload[0U] == 0x80U);
        CHECK(RoamingCodec::encodeConfigAck(payload, 5U, true, 0xDEE00U, 0x13BU) == 0U);

        bool capable = true;
        uint32_t netId = 1U;
        uint32_t sysId = 1U;
        const uint8_t legacy[5U] = { 0x80U, 0x00U, 0x00U, 0x00U, 0x00U };
        REQUIRE(RoamingCodec::decodeConfigAck(legacy, sizeof(legacy), capable, netId, sysId));
        CHECK_FALSE(capable);

        const uint8_t extended[10U] = { 0xC0U, 0x0DU, 0xEEU, 0x00U, 0x01U, 0x3BU, 0x00U, 0x00U, 0x00U, 0x00U };
        REQUIRE(RoamingCodec::decodeConfigAck(extended, sizeof(extended), capable, netId, sysId));
        CHECK(capable);
        CHECK(netId == 0xDEE00U);
        CHECK(sysId == 0x13BU);

        CHECK_FALSE(RoamingCodec::decodeConfigAck(extended, 3U, capable, netId, sysId));
        const uint8_t badWacn[6U] = { 0xC0U, 0x10U, 0x00U, 0x00U, 0x01U, 0x3BU };
        CHECK_FALSE(RoamingCodec::decodeConfigAck(badWacn, sizeof(badWacn), capable, netId, sysId));
        CHECK_FALSE(RoamingCodec::decodeConfigAck(extended, 0U, capable, netId, sysId));
    }

    SECTION("Grant_Request_Source_System") {
        uint8_t grant[ROAM_GRANT_REQ_LEN];
        ::memset(grant, 0x00U, sizeof(grant));
        REQUIRE(RoamingCodec::encodeGrantSource(grant, 0xDEE00U, 0x911U));
        const uint8_t expected[5U] = { 0x0DU, 0xEEU, 0x00U, 0x09U, 0x11U };
        for (uint32_t i = 0U; i < ROAM_GRANT_REQ_LEN; i++) {
            INFO("byte " << i);
            CHECK(grant[i] == ((i >= 4U && i <= 8U) ? expected[i - 4U] : 0x00U));
        }

        uint32_t netId = 0U;
        uint32_t sysId = 0U;
        REQUIRE(RoamingCodec::decodeGrantSource(grant, sizeof(grant), netId, sysId));
        CHECK(netId == 0xDEE00U);
        CHECK(sysId == 0x911U);

        uint8_t zero[ROAM_GRANT_REQ_LEN];
        ::memset(zero, 0x00U, sizeof(zero));
        REQUIRE(RoamingCodec::decodeGrantSource(zero, sizeof(zero), netId, sysId));
        CHECK(netId == 0U);
        CHECK(sysId == 0U);
        CHECK_FALSE(RoamingCodec::decodeGrantSource(zero, ROAM_GRANT_REQ_LEN - 1U, netId, sysId));

        zero[7U] = 0x10U;
        CHECK_FALSE(RoamingCodec::decodeGrantSource(zero, sizeof(zero), netId, sysId));

        uint8_t untouched[ROAM_GRANT_REQ_LEN];
        ::memset(untouched, 0x00U, sizeof(untouched));
        CHECK_FALSE(RoamingCodec::encodeGrantSource(untouched, 0x100000U, 0x911U));
        CHECK(untouched[4U] == 0x00U);
    }
}
