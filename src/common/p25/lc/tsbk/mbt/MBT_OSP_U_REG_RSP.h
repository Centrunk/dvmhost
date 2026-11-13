// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
/**
 * @file MBT_OSP_U_REG_RSP.h
 * @ingroup p25_ambt
 * @file MBT_OSP_U_REG_RSP.cpp
 * @ingroup p25_ambt
 */
#if !defined(__P25_LC_TSBK__MBT_OSP_U_REG_RSP_H__)
#define  __P25_LC_TSBK__MBT_OSP_U_REG_RSP_H__

#include "common/Defines.h"
#include "common/p25/lc/AMBT.h"

namespace p25
{
    namespace lc
    {
        namespace tsbk
        {
            // ---------------------------------------------------------------------------
            //  Class Declaration
            // ---------------------------------------------------------------------------

            /**
             * @brief Implements U REG RSP - Unit Registration Response (Extended Format, TIA-102.AABC-D 6.2.21.2).
             *  Used when the WACN ID of the source unit does not match the WACN ID of the site.
             *  In this release it is only used to deny such SUs.
             * @ingroup p25_ambt
             */
            class DVM_COMMON_API MBT_OSP_U_REG_RSP : public AMBT {
            public:
                /**
                 * @brief Initializes a new instance of the MBT_OSP_U_REG_RSP class.
                 */
                MBT_OSP_U_REG_RSP();

                /**
                 * @brief Decode a alternate trunking signalling block.
                 *  This message is outbound-only; decoding is not supported.
                 * @param[in] dataHeader P25 PDU data header
                 * @param[in] blocks P25 PDU data blocks
                 * @returns bool Always false.
                 */
                bool decodeMBT(const data::DataHeader& dataHeader, const data::DataBlock* blocks) override;
                /**
                 * @brief Encode a alternate trunking signalling block.
                 * @param[out] dataHeader P25 PDU data header
                 * @param[out] pduUserData P25 PDU user data
                 */
                void encodeMBT(data::DataHeader& dataHeader, uint8_t* pduUserData) override;

                /**
                 * @brief Returns a string that represents the current AMBT.
                 * @param isp Flag indicating whether the string should describe the inbound form.
                 * @returns std::string String representation of the AMBT.
                 */
                std::string toString(bool isp = false) override;

            public:
                /**
                 * @brief SUID WACN ID of the registering SU (20-bit).
                 */
                DECLARE_PROPERTY(uint32_t, suidNetId, SUIDNetId);
                /**
                 * @brief SUID System ID of the registering SU (12-bit).
                 */
                DECLARE_PROPERTY(uint32_t, suidSysId, SUIDSysId);
            };
        } // namespace tsbk
    } // namespace lc
} // namespace p25

#endif // __P25_LC_TSBK__MBT_OSP_U_REG_RSP_H__
