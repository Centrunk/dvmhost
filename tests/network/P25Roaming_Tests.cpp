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
