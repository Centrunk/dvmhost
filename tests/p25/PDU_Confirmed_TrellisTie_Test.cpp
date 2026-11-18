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
#include "common/p25/data/DataBlock.h"
#include "common/p25/data/DataHeader.h"
#include "common/edac/CRC.h"
#include "common/Log.h"

using namespace p25;
using namespace p25::defines;
using namespace p25::data;

#include <catch2/catch_test_macros.hpp>
#include <cstring>

/*
** Over-the-air confirmed data blocks captured from a hotspot (MMDVM_HS_Hat, ADF7021) receiving an
** APX subscriber. Each named block arrived with a few single-level symbol errors that leave it
** equidistant from several codewords, so a plain maximum-likelihood decode can return the wrong one;
** the previous greedy point fixer also failed on them. The expected contents were established
** independently of the Trellis decoder: by the packet CRC-32 sent by the subscriber, and for the
** rekey packet also by its UDP checksum.
*/

static DataHeader confirmedHeader()
{
    DataHeader header = DataHeader();
    header.setFormat(PDUFormatType::CONFIRMED);
    header.setSAP(PDUSAP::USER_DATA);
    return header;
}

TEST_CASE("P25 PDU Confirmed Trellis tie, 4-block LRRP uplink", "[p25][pdu][trellis]") {
    g_logDisplayLevel = 1U;

    // 4-block uplink, IPv4/UDP from 10.148.1.72 to 172.28.0.55; block 1 is the tied block
    const uint8_t RAW[4U][P25_PDU_FEC_LENGTH_BYTES] = {
        { 0x2C, 0xE3, 0x23, 0xE2, 0xEE, 0x58, 0xE2, 0x92, 0xF2, 0x93, 0x2A, 0xB4, 0xA2, 0x72, 0xF2, 0x32, 0x22, 0x7F, 0x67, 0x57, 0x2E, 0x2F, 0x2D, 0xC7, 0xF0 },
        { 0x2C, 0x73, 0xF0, 0xE4, 0xEB, 0x38, 0xB2, 0xE6, 0x72, 0x53, 0x72, 0x6E, 0x6B, 0x25, 0x12, 0xE7, 0x22, 0x26, 0x01, 0xD7, 0x31, 0xC2, 0x0D, 0x5A, 0xD0 },
        { 0x2B, 0xA9, 0x05, 0x37, 0xE2, 0xF3, 0x2D, 0x7D, 0xCB, 0x61, 0x27, 0x23, 0xF8, 0xA1, 0x80, 0x81, 0xD3, 0x7E, 0x25, 0x34, 0x34, 0xAF, 0x1A, 0xC4, 0x20 },
        { 0x26, 0x22, 0x22, 0x22, 0x22, 0xD2, 0xAD, 0xF2, 0x22, 0x22, 0x22, 0xEB, 0xE2, 0xF2, 0x22, 0x22, 0x22, 0x56, 0x9B, 0x22, 0x22, 0x22, 0x22, 0xE7, 0xF0 } };

    const uint8_t EXPECTED_BLOCK1[P25_PDU_CONFIRMED_DATA_LENGTH_BYTES] = {
        0x01, 0x48, 0xAC, 0x1C, 0x00, 0x37, 0xE3, 0x58, 0x0F, 0xA1, 0x00, 0x19, 0xA5, 0x09, 0x0B, 0x0F };

    DataHeader header = confirmedHeader();

    uint8_t userData[4U * P25_PDU_CONFIRMED_DATA_LENGTH_BYTES];
    ::memset(userData, 0x00U, sizeof(userData));

    for (uint32_t i = 0U; i < 4U; i++) {
        DataBlock block = DataBlock();
        INFO("block " << i);
        REQUIRE(block.decode(RAW[i], header));
        REQUIRE(block.getSerialNo() == i);
        block.getData(userData + i * P25_PDU_CONFIRMED_DATA_LENGTH_BYTES);
    }

    REQUIRE(::memcmp(userData + P25_PDU_CONFIRMED_DATA_LENGTH_BYTES, EXPECTED_BLOCK1, P25_PDU_CONFIRMED_DATA_LENGTH_BYTES) == 0);

    // the subscriber's packet CRC-32 ($8833009A) closes the last block
    REQUIRE(edac::CRC::checkCRC32(userData, sizeof(userData)));
}

TEST_CASE("P25 PDU Confirmed Trellis tie, KMM rekey uplink", "[p25][pdu][trellis]") {
    g_logDisplayLevel = 1U;

    // block 2 of a 4-block uplink carrying a KMM over UDP from 10.148.1.72 to 172.28.0.20:64414;
    // it is equidistant (5 single-level symbol errors) from four codewords
    const uint8_t RAW_BLOCK2[P25_PDU_FEC_LENGTH_BYTES] = {
        0x2F, 0x22, 0x22, 0x22, 0x22, 0xE7, 0x69, 0xA2, 0x22, 0x22, 0x22, 0x22, 0x38, 0xA2, 0x22, 0x22,
        0x22, 0xD2, 0xAD, 0x22, 0x22, 0x22, 0x22, 0xB2, 0x20 };

    const uint8_t EXPECTED_BLOCK2[P25_PDU_CONFIRMED_DATA_LENGTH_BYTES] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x08, 0x80 };

    DataHeader header = confirmedHeader();

    DataBlock block = DataBlock();
    REQUIRE(block.decode(RAW_BLOCK2, header));
    REQUIRE(block.getSerialNo() == 2U);

    uint8_t packet[4U * P25_PDU_CONFIRMED_DATA_LENGTH_BYTES] = {
        // blocks 0 and 1 (decoded without error on the same transmission)
        0x51, 0x00, 0x45, 0x00, 0x00, 0x35, 0x44, 0x8A, 0x00, 0x00, 0x40, 0x11, 0x7E, 0x22, 0x0A, 0x94,
        0x01, 0x48, 0xAC, 0x1C, 0x00, 0x14, 0xD8, 0xB4, 0xFB, 0x9E, 0x00, 0x21, 0xA1, 0xD9, 0x00, 0x00 };
    block.getData(packet + 32U);
    REQUIRE(::memcmp(packet + 32U, EXPECTED_BLOCK2, P25_PDU_CONFIRMED_DATA_LENGTH_BYTES) == 0);

    // block 3 (decoded without error): 7 octets of data, 5 octets of pad, then the packet CRC-32
    const uint8_t BLOCK3[16U] = { 0x98, 0x96, 0x7F, 0x00, 0x23, 0x5B, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE7, 0x17, 0xB9, 0x66 };
    ::memcpy(packet + 48U, BLOCK3, sizeof(BLOCK3));
    REQUIRE(edac::CRC::checkCRC32(packet, sizeof(packet)));

    // UDP checksum over the IPv4 pseudo header and the 33-octet UDP datagram at offset 22
    uint32_t sum = 0x0A94U + 0x0148U + 0xAC1CU + 0x0014U + 0x0011U + 0x0021U;
    for (uint32_t i = 0U; i < 33U; i += 2U) {
        uint32_t word = (uint32_t)packet[22U + i] << 8;
        if (i + 1U < 33U)
            word |= packet[23U + i];
        sum += word;
    }

    while ((sum >> 16) != 0U)
        sum = (sum & 0xFFFFU) + (sum >> 16);
    REQUIRE(sum == 0xFFFFU);
}
