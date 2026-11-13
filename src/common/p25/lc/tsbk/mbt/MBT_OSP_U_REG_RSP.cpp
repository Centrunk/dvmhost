// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h"

using namespace p25;
using namespace p25::defines;
using namespace p25::lc;
using namespace p25::lc::tsbk;

#include <cassert>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the MBT_OSP_U_REG_RSP class. */

MBT_OSP_U_REG_RSP::MBT_OSP_U_REG_RSP() : AMBT(),
    m_suidNetId(0U),
    m_suidSysId(0U)
{
    m_lco = TSBKO::IOSP_U_REG;
}

/* Decode a alternate trunking signalling block. */

bool MBT_OSP_U_REG_RSP::decodeMBT(const data::DataHeader& dataHeader, const data::DataBlock* blocks)
{
    assert(blocks != nullptr);

    // outbound-only message
    return false;
}

/* Encode a alternate trunking signalling block. */

void MBT_OSP_U_REG_RSP::encodeMBT(data::DataHeader& dataHeader, uint8_t* pduUserData)
{
    assert(pduUserData != nullptr);

    // header octets 8 and 9 carry the upper 16 bits of the SUID WACN ID (TIA-102.AABC-D Figure 6.2.21-2)
    dataHeader.setAMBTField8((m_suidNetId >> 12) & 0xFFU);                          // WACN ID (b19-b12)
    dataHeader.setAMBTField9((m_suidNetId >> 4) & 0xFFU);                           // WACN ID (b11-b4)

    /** Block 1 */
    pduUserData[0U] = (uint8_t)(((m_suidNetId & 0x0FU) << 4) +                      // WACN ID (b3-b0)
        ((m_suidSysId >> 8) & 0x0FU));                                              // System ID (b11-b8)
    pduUserData[1U] = (uint8_t)(m_suidSysId & 0xFFU);                               // System ID (b7-b0)
    SET_UINT24(m_dstId, pduUserData, 2U);                                           // Source ID (SUID Unit ID)
    pduUserData[5U] = m_response & 0x03U;                                           // Registration Value

    AMBT::encode(dataHeader, pduUserData);
}

/* Returns a string that represents the current AMBT. */

std::string MBT_OSP_U_REG_RSP::toString(bool isp)
{
    return std::string("TSBKO, IOSP_U_REG (Unit Registration Response - Extended)");
}
