// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Modem Host Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
/**
 * @file P25WuidLookup.h
 * @ingroup host_lookups
 * @file P25WuidLookup.cpp
 * @ingroup host_lookups
 */
#if !defined(__P25_WUID_LOOKUP_H__)
#define __P25_WUID_LOOKUP_H__

#include "Defines.h"

#include <map>
#include <mutex>

namespace p25
{
    namespace lookups
    {
        // ---------------------------------------------------------------------------
        //  Class Declaration
        // ---------------------------------------------------------------------------

        /**
         * @brief Implements the Working Unit ID (WUID) pool assigned to roaming subscriber units.
         *  Per TIA-102.AABD-B 6.2, a foreign SU (different WACN ID and/or System ID) is assigned a WUID
         *  from an operator-controlled pool that cannot be the Unit ID portion of a Home SUID.
         * @ingroup host_lookups
         */
        class HOST_SW_API P25WuidLookup {
        public:
            /**
             * @brief Subscriber Unit ID (SUID) of a registering subscriber unit.
             * @ingroup host_lookups
             */
            struct SUID {
                uint32_t netId;     //!< WACN ID (20-bit).
                uint32_t sysId;     //!< System ID (12-bit).
                uint32_t unitId;    //!< Unit ID (24-bit).
            };

            /**
             * @brief Initializes a new instance of the P25WuidLookup class.
             */
            P25WuidLookup();

            /**
             * @brief Validates a WUID pool range.
             * @param start First WUID of the pool (inclusive).
             * @param end Last WUID of the pool (inclusive).
             * @returns bool True if 0 < start <= end and end is below the reserved WUID range; otherwise, false.
             */
            static bool validRange(uint32_t start, uint32_t end);

            /**
             * @brief Configures the WUID pool and clears all assignments.
             * @param start First WUID of the pool (inclusive).
             * @param end Last WUID of the pool (inclusive).
             * @returns bool True if the pool was configured; false if the range is invalid (pool disabled).
             */
            bool setPool(uint32_t start, uint32_t end);
            /**
             * @brief Removes the pool and all assignments.
             */
            void clear();

            /**
             * @brief Gets whether a WUID pool is configured.
             * @returns bool True if a pool is configured; otherwise, false.
             */
            bool enabled() const;
            /**
             * @brief Gets the first WUID of the pool.
             * @returns uint32_t First WUID, or 0 if no pool is configured.
             */
            uint32_t poolStart() const;
            /**
             * @brief Gets the last WUID of the pool.
             * @returns uint32_t Last WUID, or 0 if no pool is configured.
             */
            uint32_t poolEnd() const;

            /**
             * @brief Allocates a WUID for a roaming SU.
             * @param suid SUID of the registering SU.
             * @returns uint32_t The SU's existing WUID, the lowest free pool WUID, or 0 if the pool is exhausted or disabled.
             */
            uint32_t allocate(const SUID& suid);
            /**
             * @brief Releases an assigned WUID.
             * @param wuid WUID to release.
             * @returns bool True if an assignment was removed; otherwise, false.
             */
            bool release(uint32_t wuid);

            /**
             * @brief Finds the WUID assigned to an SUID.
             * @param suid SUID to look up.
             * @param[out] wuid Assigned WUID when found.
             * @returns bool True if the SUID has an assigned WUID; otherwise, false.
             */
            bool findBySuid(const SUID& suid, uint32_t& wuid) const;
            /**
             * @brief Finds the SUID assigned to a WUID.
             * @param wuid WUID to look up.
             * @param[out] suid Assigned SUID when found.
             * @returns bool True if the WUID is assigned; otherwise, false.
             */
            bool findByWuid(uint32_t wuid, SUID& suid) const;

            /**
             * @brief Determines whether a WUID lies within the configured pool.
             * @param wuid WUID to test.
             * @returns bool True if a pool is configured and the WUID lies within it; otherwise, false.
             */
            bool isPoolWuid(uint32_t wuid) const;
            /**
             * @brief Gets the number of assigned WUIDs.
             * @returns uint32_t Number of assigned WUIDs.
             */
            uint32_t count() const;

        private:
            mutable std::mutex m_mutex;
            uint32_t m_start;
            uint32_t m_end;
            std::map<uint64_t, uint32_t> m_bySuid;
            std::map<uint32_t, SUID> m_byWuid;

            /**
             * @brief Packs an SUID into a 56-bit map key.
             * @param suid SUID to pack.
             * @returns uint64_t Packed key (WACN ID, System ID, Unit ID).
             */
            static uint64_t key(const SUID& suid);
        };
    } // namespace lookups
} // namespace p25

#endif // __P25_WUID_LOOKUP_H__
