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
 * @file P25Roaming.h
 * @ingroup network_core
 * @file P25Roaming.cpp
 * @ingroup network_core
 */
#if !defined(__P25_ROAMING_H__)
#define __P25_ROAMING_H__

#include "common/Defines.h"

#include <cstdint>

namespace network
{
    namespace roaming
    {
        // ---------------------------------------------------------------------------
        //  Constants
        // ---------------------------------------------------------------------------

        /**
         * @addtogroup network_core
         * @{
         */

        /** @brief ROAMING message version carried in common header byte 0. */
        const uint8_t ROAM_VERSION = 1U;
        /** @brief Hop count set by a ROAMING message originator; each forwarding FNE decrements it. */
        const uint8_t ROAM_DEFAULT_HOP_COUNT = 8U;

        /** @brief Length of the ROAMING common header (version, hop count, transaction ID) in bytes. */
        const uint32_t ROAM_HEADER_LEN = 6U;
        /** @brief Length of a SUID field group (WACN 3, System ID 2, Unit ID 3) in bytes. */
        const uint32_t ROAM_SUID_LEN = 8U;
        /** @brief Length of an RFSS identity field group (WACN 3, System ID 2, RFSS ID 1) in bytes (BACA 3.4.1.1). */
        const uint32_t ROAM_RFSS_LEN = 6U;

        /** @brief Total ROAM_SERVING_REG length in bytes. */
        const uint32_t MSG_ROAM_SERVING_REG_LEN = 21U;
        /** @brief Total ROAM_SERVING_REG_RSP length in bytes. */
        const uint32_t MSG_ROAM_SERVING_REG_RSP_LEN = 21U;
        /** @brief Total ROAM_SERVING_DEREG length in bytes. */
        const uint32_t MSG_ROAM_SERVING_DEREG_LEN = 20U;
        /** @brief Total ROAM_SERVING_DEREG_RSP length in bytes. */
        const uint32_t MSG_ROAM_SERVING_DEREG_RSP_LEN = 15U;
        /** @brief Total ROAM_HOME_DEREG length in bytes. */
        const uint32_t MSG_ROAM_HOME_DEREG_LEN = 15U;
        /** @brief Total ROAM_HOME_DEREG_RSP length in bytes. */
        const uint32_t MSG_ROAM_HOME_DEREG_RSP_LEN = 15U;
        /** @brief Total ROAM_QUERY length in bytes. */
        const uint32_t MSG_ROAM_QUERY_LEN = 15U;
        /** @brief Total ROAM_QUERY_RSP length in bytes. */
        const uint32_t MSG_ROAM_QUERY_RSP_LEN = 16U;
        /** @brief Total ROAM_GEN_RSP length in bytes. */
        const uint32_t MSG_ROAM_GEN_RSP_LEN = 8U;
        /** @brief Largest ROAMING message in bytes. */
        const uint32_t MSG_ROAM_MAX_LEN = 21U;

        /** @brief Length of UNIT_REG_SUID, UNIT_DEREG_SUID and GRP_UNAFFIL_SUID announcements in bytes. */
        const uint32_t MSG_ANNC_UNIT_REG_SUID_LEN = 8U;
        /** @brief Length of a GRP_AFFIL_SUID announcement in bytes. */
        const uint32_t MSG_ANNC_GRP_AFFIL_SUID_LEN = 11U;
        /** @brief Length of the entry count that starts a bulk SUID announcement in bytes. */
        const uint32_t MSG_ANNC_SUID_BULK_HDR_LEN = 4U;
        /** @brief Length of a NET_FUNC::GRANT_REQ message in bytes (equals MSG_HDR_SIZE). */
        const uint32_t ROAM_GRANT_REQ_LEN = 24U;

        /** @brief Largest WACN ID (20-bit). */
        const uint32_t ROAM_MAX_WACN = 0xFFFFFU;
        /** @brief Largest System ID (12-bit). */
        const uint32_t ROAM_MAX_SYSID = 0xFFFU;
        /** @brief Largest Unit ID (24-bit). */
        const uint32_t ROAM_MAX_UNIT_ID = 0xFFFFFFU;
        /** @brief First WACN ID of the protected range that must never be configured (BEE00 - BEEFF). */
        const uint32_t ROAM_WACN_PROTECTED_START = 0xBEE00U;
        /** @brief Last WACN ID of the protected range that must never be configured (BEE00 - BEEFF). */
        const uint32_t ROAM_WACN_PROTECTED_END = 0xBEEFFU;

        /** @brief Home registration lifetimes must be greater than this many seconds (BACA 5.5.1(2a)(i)). */
        const uint32_t ROAM_MIN_EXPIRES = 14400U;
        /** @brief Default home registration lifetime returned as expires, in seconds. */
        const uint32_t ROAM_DEFAULT_EXPIRES = 18000U;
        /** @brief Default time a host waits for a Serving Registration response, in milliseconds. */
        const uint32_t ROAM_DEFAULT_HOME_TIMEOUT_MS = 5000U;
        /** @brief RetryTime after a FAILED Serving Registration, in milliseconds (BACA 5.5 Gen Req 10, Table 58). */
        const uint32_t ROAM_RETRY_TIME_MS = 10000U;
        /** @brief Percentage of expires after which a serving host refreshes its Serving Registration. */
        const uint32_t ROAM_REFRESH_PERCENT = 80U;
        /** @brief Time after which an FNE discards a forwarded transaction with no response, in milliseconds. */
        const uint32_t ROAM_FNE_PENDING_TIMEOUT_MS = 10000U;

        /** @brief Version of the RPTC p25Roaming JSON object. */
        const uint32_t ROAM_CONFIG_VERSION = 1U;
        /** @brief RPTC ACK payload byte 0 flag: master uses the alternate diagnostics port. */
        const uint8_t CONFIG_ACK_ALT_DIAG_PORT = 0x80U;
        /** @brief RPTC ACK payload byte 0 flag: master is P25 roaming capable. */
        const uint8_t CONFIG_ACK_ROAMING_CAPABLE = 0x40U;
        /** @brief Length of the extended RPTC ACK payload (flags 1, WACN 3, System ID 2) in bytes. */
        const uint32_t CONFIG_ACK_ROAMING_LEN = 6U;

        /** @brief SERVING_REG_RSP flags bit 7: radio inhibited (BACA 3.8.2.15 u-radinhib). */
        const uint8_t ROAM_FLAG_RADIO_INHIBITED = 0x80U;

        /** @} */

        /**
         * @brief ROAMING result codes (TIA-102.BACA-B Annex A / 6 failure code values).
         * @ingroup network_core
         */
        namespace RoamResult {
            /** @brief Result Codes */
            enum E : uint8_t {
                SUCCESS = 0x00U,                        //!< Success
                MME_SU_REG_DISALLOWED = 0x18U,          //!< Serving system not permitted to serve the SU
                MME_MUST_CONFIRM_SU_PRESENCE = 0x1BU,   //!< Home requires a confirmed presence
                GEN_PROC_UNSUPPORTED = 0x1CU,           //!< Procedure not supported
                MME_SU_UNKNOWN = 0x22U,                 //!< SU unknown at the home (also "Not Found")
                MME_SU_AUTHEN_REQUIRED = 0x2FU,         //!< SU authentication required
                MME_OBJ_NOT_REG_AT_SERV = 0x57U         //!< Object not registered at the named serving RFSS
            };
        }

        /**
         * @brief Serving Registration presence values (BACA 5.5.1(1)).
         * @ingroup network_core
         */
        namespace RoamPresence {
            /** @brief Presence */
            enum E : uint8_t {
                NOT_CONFIRMED = 0U,                     //!< Presence not confirmed (timer refresh)
                CONFIRMED = 1U                          //!< Presence confirmed by an SU registration on air
            };
        }

        /**
         * @brief Serving Registration Response access values (BACA 3.8.2.1 u-access).
         * @ingroup network_core
         */
        namespace RoamAccess {
            /** @brief Access */
            enum E : uint8_t {
                NONE = 0U,                              //!< No access
                FULL = 1U,                              //!< Full access
                EMERGENCY_ONLY = 2U                     //!< Emergency access only
            };
        }

        /**
         * @brief Home Deregistration qualifier values (BACA 5.5.5).
         * @ingroup network_core
         */
        namespace RoamQualifier {
            /** @brief Qualifier */
            enum E : uint8_t {
                ROAMED = 0U,                            //!< The SU registered at another serving RFSS
                NON_ROAMED = 1U                         //!< The SU is no longer authorized (policy removal)
            };
        }

        /**
         * @brief Query type values (BACA 2.1.4.1.4).
         * @ingroup network_core
         */
        namespace RoamQueryType {
            /** @brief Query Type */
            enum E : uint8_t {
                NORMAL_HOME = 0U,                       //!< Normal Home query
                FORCED = 1U,                            //!< Forced query (serving host commands re-registration)
                CONFIRMED = 2U,                         //!< Confirmed query (unsupported)
                SERVING = 3U                            //!< Serving query (unsupported)
            };
        }

        /**
         * @brief ROAMING decode status.
         * @ingroup network_core
         */
        namespace RoamDecode {
            /** @brief Decode Status */
            enum E : uint8_t {
                OK = 0U,                                //!< Decoded
                MALFORMED_LENGTH = 1U,                  //!< Length does not match the sub-function
                BAD_VERSION = 2U,                       //!< Version is not ROAM_VERSION
                OUT_OF_RANGE = 3U,                      //!< WACN ID or System ID out of range
                UNKNOWN_SUBFUNC = 4U                    //!< Sub-function is not a known ROAMING sub-function
            };
        }

        // ---------------------------------------------------------------------------
        //  Structure Declaration
        // ---------------------------------------------------------------------------

        /**
         * @brief P25 Subscriber Unit ID: WACN ID, System ID and Unit ID (TIA-102.BACA-B 2.1.3.1.1).
         * @ingroup network_core
         */
        struct DVM_COMMON_API SUID {
            uint32_t netId = 0U;                        //!< WACN ID (20-bit).
            uint32_t sysId = 0U;                        //!< System ID (12-bit).
            uint32_t unitId = 0U;                       //!< Unit ID (24-bit).

            /**
             * @brief Packs the SUID into its 64-bit table key, (WACN << 36) | (SysID << 24) | UnitID.
             * @returns uint64_t Packed SUID.
             */
            uint64_t pack() const;
            /**
             * @brief Unpacks a 64-bit SUID table key.
             * @param key Packed SUID.
             * @returns SUID Unpacked SUID.
             */
            static SUID unpack(uint64_t key);
            /**
             * @brief Checks the WACN ID, System ID and Unit ID ranges.
             * @returns bool True if every field fits its width; otherwise, false.
             */
            bool valid() const;
            /**
             * @brief Compares two SUIDs.
             * @param other SUID to compare.
             * @returns bool True if all fields are equal; otherwise, false.
             */
            bool operator==(const SUID& other) const;
            /**
             * @brief Checks the WACN ID and System ID ranges.
             * @param netId WACN ID.
             * @param sysId System ID.
             * @returns bool True if the WACN ID is at most $FFFFF and the System ID at most $FFF; otherwise, false.
             */
            static bool validSystem(uint32_t netId, uint32_t sysId);
            /**
             * @brief Packs a WACN ID and System ID into a 32-bit system table key.
             * @param netId WACN ID.
             * @param sysId System ID.
             * @returns uint32_t (WACN << 12) | SysID.
             */
            static uint32_t systemKey(uint32_t netId, uint32_t sysId);
        };

        // ---------------------------------------------------------------------------
        //  Structure Declaration
        // ---------------------------------------------------------------------------

        /**
         * @brief Identity of an RFSS: WACN ID, System ID and RFSS ID (TIA-102.BACA-B 3.4.1.1).
         * @ingroup network_core
         */
        struct DVM_COMMON_API RfssIdentity {
            uint32_t netId = 0U;                        //!< WACN ID (20-bit).
            uint32_t sysId = 0U;                        //!< System ID (12-bit).
            uint8_t rfssId = 0U;                        //!< RFSS ID.

            /**
             * @brief Checks the WACN ID and System ID ranges.
             * @returns bool True if both fit their widths; otherwise, false.
             */
            bool valid() const;
            /**
             * @brief Compares two RFSS identities.
             * @param other RFSS identity to compare.
             * @returns bool True if all fields are equal; otherwise, false.
             */
            bool operator==(const RfssIdentity& other) const;
        };
    } // namespace roaming
} // namespace network

#endif // __P25_ROAMING_H__
