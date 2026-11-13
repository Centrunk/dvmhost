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
#include "common/p25/P25Defines.h"
#include "host/p25/lookups/P25WuidLookup.h"

#include <catch2/catch_test_macros.hpp>

using namespace p25::lookups;

namespace {
    P25WuidLookup::SUID suid(uint32_t sysId, uint32_t unitId)
    {
        P25WuidLookup::SUID ret;
        ret.netId = 0xBB800U;
        ret.sysId = sysId;
        ret.unitId = unitId;
        return ret;
    }
}

TEST_CASE("P25 WUID lookup range validation", "[p25][roaming][wuid]") {
    CHECK_FALSE(P25WuidLookup::validRange(0U, 10U));
    CHECK_FALSE(P25WuidLookup::validRange(20U, 10U));
    CHECK_FALSE(P25WuidLookup::validRange(100U, p25::defines::WUID_FNE));
    CHECK(P25WuidLookup::validRange(100U, 100U));
    CHECK(P25WuidLookup::validRange(1U, p25::defines::WUID_FNE - 1U));
}

TEST_CASE("P25 WUID lookup is inert without a pool", "[p25][roaming][wuid]") {
    P25WuidLookup lookup;
    CHECK_FALSE(lookup.enabled());
    CHECK_FALSE(lookup.isPoolWuid(0U));
    CHECK_FALSE(lookup.isPoolWuid(9000000U));
    CHECK(lookup.allocate(suid(0x002U, 1001U)) == 0U);
    CHECK_FALSE(lookup.setPool(0U, 10U));
    CHECK_FALSE(lookup.enabled());
}

TEST_CASE("P25 WUID lookup allocation", "[p25][roaming][wuid]") {
    P25WuidLookup lookup;
    REQUIRE(lookup.setPool(9000000U, 9000002U));

    SECTION("Boundaries") {
        CHECK_FALSE(lookup.isPoolWuid(8999999U));
        CHECK(lookup.isPoolWuid(9000000U));
        CHECK(lookup.isPoolWuid(9000002U));
        CHECK_FALSE(lookup.isPoolWuid(9000003U));
    }

    SECTION("Lowest_Free_And_Reregistration") {
        CHECK(lookup.allocate(suid(0x002U, 1001U)) == 9000000U);
        CHECK(lookup.allocate(suid(0x003U, 1001U)) == 9000001U);
        CHECK(lookup.allocate(suid(0x002U, 1001U)) == 9000000U);
        CHECK(lookup.count() == 2U);
    }

    SECTION("Exhaustion_And_Reuse") {
        CHECK(lookup.allocate(suid(0x002U, 1U)) == 9000000U);
        CHECK(lookup.allocate(suid(0x002U, 2U)) == 9000001U);
        CHECK(lookup.allocate(suid(0x002U, 3U)) == 9000002U);
        CHECK(lookup.allocate(suid(0x002U, 4U)) == 0U);

        CHECK(lookup.release(9000001U));
        CHECK_FALSE(lookup.release(9000001U));
        CHECK(lookup.allocate(suid(0x002U, 4U)) == 9000001U);
    }

    SECTION("Bidirectional_Lookup") {
        const uint32_t wuid = lookup.allocate(suid(0x2A5U, 0x0F4240U));
        REQUIRE(wuid == 9000000U);

        uint32_t found = 0U;
        CHECK(lookup.findBySuid(suid(0x2A5U, 0x0F4240U), found));
        CHECK(found == wuid);
        CHECK_FALSE(lookup.findBySuid(suid(0x2A6U, 0x0F4240U), found));

        P25WuidLookup::SUID back;
        REQUIRE(lookup.findByWuid(wuid, back));
        CHECK(back.netId == 0xBB800U);
        CHECK(back.sysId == 0x2A5U);
        CHECK(back.unitId == 0x0F4240U);
        CHECK_FALSE(lookup.findByWuid(9000001U, back));
    }

    SECTION("Release_Unknown_And_Clear") {
        CHECK_FALSE(lookup.release(1234U));
        lookup.allocate(suid(0x002U, 1U));
        lookup.clear();
        CHECK_FALSE(lookup.enabled());
        CHECK(lookup.count() == 0U);
    }
}

TEST_CASE("P25 WUID lookup single-ID pool", "[p25][roaming][wuid]") {
    P25WuidLookup lookup;
    REQUIRE(lookup.setPool(500U, 500U));
    CHECK(lookup.allocate(suid(0x002U, 1U)) == 500U);
    CHECK(lookup.allocate(suid(0x002U, 2U)) == 0U);
}
