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
#include "common/p25/lc/tsbk/IOSP_ACK_RSP.h"
#include "common/p25/lc/tsbk/OSP_LOC_REG_RSP.h"
#include "common/p25/lc/tsbk/OSP_U_DEREG_ACK.h"
#include "common/p25/lc/tsbk/IOSP_U_REG.h"
#include "common/p25/lc/tsbk/TSBKFactory.h"
#include "common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h"
#include "common/p25/data/DataHeader.h"
#include "common/p25/P25Defines.h"
#include "common/p25/SiteData.h"

using namespace p25;
using namespace p25::defines;
using namespace p25::lc;
using namespace p25::lc::tsbk;

#include <catch2/catch_test_macros.hpp>
#include <cstring>

TEST_CASE("TSBK registration responses", "[p25][tsbk][registration]") {
    // known-answer vectors are derived by hand from TIA-102.AABC-D figures, not from round trips
    const SiteData previousSiteData = TSBK::getSiteData();
    TSBK::setSiteData(SiteData(0xBB800U, 0x2A5U, 0x12U, 0x34U, 0x01U, 1U, 1U, 0x00U, 0));

    SECTION("LOC_REG_RSP_Known_Bytes_Figure_6_2_23_1") {
        OSP_LOC_REG_RSP osp;
        osp.setResponse(ResponseCode::DENY);
        osp.setDstId(0xABCDU);
        osp.setSrcId(0x0F4240U);

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        osp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x02U, 0xABU, 0xCDU, 0x12U, 0x34U, 0x0FU, 0x42U, 0x40U };
        CHECK((raw[0U] & 0x3FU) == TSBKO::OSP_LOC_REG_RSP);
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    SECTION("U_REG_RSP_Abbreviated_Roaming_Known_Bytes_Figure_6_2_21_1") {
        IOSP_U_REG iosp;
        iosp.setResponse(ResponseCode::DENY);
        iosp.setSUIDSysId(0x2A5U);
        iosp.setDstId(0x0F4240U);                                                   // Source ID (SUID Unit ID)
        iosp.setSrcId(0x7A1200U);                                                   // Source Address (WUID)

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        iosp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x22U, 0xA5U, 0x0FU, 0x42U, 0x40U, 0x7AU, 0x12U, 0x00U };
        CHECK((raw[0U] & 0x3FU) == TSBKO::IOSP_U_REG);
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    SECTION("U_REG_RSP_Abbreviated_Home_Unchanged") {
        IOSP_U_REG iosp;
        iosp.setResponse(ResponseCode::ACCEPT);
        iosp.setDstId(1001U);
        iosp.setSrcId(1001U);

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        iosp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x02U, 0xA5U, 0x00U, 0x03U, 0xE9U, 0x00U, 0x03U, 0xE9U };
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    SECTION("U_REG_RSP_Extended_Known_Bytes_Figure_6_2_21_2") {
        MBT_OSP_U_REG_RSP osp;
        osp.setResponse(ResponseCode::DENY);
        osp.setSUIDNetId(0x12345U);
        osp.setSUIDSysId(0x2A5U);
        osp.setDstId(0x0F4240U);                                                    // Source ID (SUID Unit ID)
        osp.setSrcId(0x000000U);                                                    // Source Address ("No one")

        data::DataHeader header;
        uint8_t raw[P25_PDU_UNCONFIRMED_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        osp.encodeMBT(header, raw);

        CHECK(header.getFormat() == PDUFormatType::AMBT);
        CHECK(header.getSAP() == PDUSAP::TRUNK_CTRL);
        CHECK(header.getOutbound());
        CHECK(header.getBlocksToFollow() == 1U);
        CHECK(header.getLLId() == 0x000000U);
        CHECK(header.getAMBTOpcode() == TSBKO::IOSP_U_REG);
        CHECK(header.getAMBTField8() == 0x12U);
        CHECK(header.getAMBTField9() == 0x34U);

        const uint8_t expected[8U] = { 0x52U, 0xA5U, 0x0FU, 0x42U, 0x40U, 0x02U, 0x00U, 0x00U };
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("data octet " << i);
            CHECK(raw[i] == expected[i]);
        }
    }

    SECTION("U_DEREG_ACK_Roaming_Known_Bytes_Figure_6_2_22_1") {
        OSP_U_DEREG_ACK osp;
        osp.setSUIDNetId(0x12345U);
        osp.setSUIDSysId(0x6B7U);
        osp.setDstId(0x0F4240U);                                                    // Source ID (SUID Unit ID)

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        osp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x00U, 0x12U, 0x34U, 0x56U, 0xB7U, 0x0FU, 0x42U, 0x40U };
        CHECK((raw[0U] & 0x3FU) == TSBKO::OSP_U_DEREG_ACK);
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    SECTION("U_DEREG_ACK_Home_Unchanged") {
        OSP_U_DEREG_ACK osp;
        osp.setDstId(1001U);

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        osp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x00U, 0xBBU, 0x80U, 0x02U, 0xA5U, 0x00U, 0x03U, 0xE9U };
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    SECTION("ACK_RSP_FNE_Target_SUID_Known_Bytes_Figure_6_2_1_2") {
        IOSP_ACK_RSP iosp;
        iosp.setAIV(true);
        iosp.setEX(true);
        iosp.setService(TSBKO::IOSP_U_REG);
        iosp.setSUIDNetId(0x12345U);
        iosp.setSUIDSysId(0x6B7U);
        iosp.setSrcId(0x0F4240U);                                                   // Target ID (SUID Unit ID)

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        iosp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0xECU, 0x12U, 0x34U, 0x56U, 0xB7U, 0x0FU, 0x42U, 0x40U };
        CHECK((raw[0U] & 0x3FU) == TSBKO::IOSP_ACK_RSP);
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    SECTION("ACK_RSP_FNE_Extended_Home_Unchanged") {
        IOSP_ACK_RSP iosp;
        iosp.setAIV(true);
        iosp.setEX(true);
        iosp.setService(TSBKO::IOSP_U_REG);
        iosp.setSrcId(1001U);

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        iosp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0xECU, 0xBBU, 0x80U, 0x02U, 0xA5U, 0x00U, 0x03U, 0xE9U };
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    TSBK::setSiteData(previousSiteData);
}
