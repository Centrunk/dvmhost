// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
/**
 * @file SuidRegistrationTable.h
 * @ingroup fne_network
 * @file SuidRegistrationTable.cpp
 * @ingroup fne_network
 */
#if !defined(__SUID_REGISTRATION_TABLE_H__)
#define __SUID_REGISTRATION_TABLE_H__

#include "fne/Defines.h"
#include "common/network/P25Roaming.h"

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace network
{
    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Stores foreign (roaming) SU registrations and group affiliations by packed SUID and owning peer.
     *  Own-system units stay in the per-peer affiliation lookups keyed by bare Unit ID.
     * @ingroup fne_network
     */
    class HOST_SW_API SuidRegistrationTable {
    public:
        /**
         * @brief One foreign SU known behind a peer.
         * @ingroup fne_network
         */
        struct Entry {
            roaming::SUID suid;                         //!< Foreign SUID.
            uint32_t peerId = 0U;                       //!< Peer that announced the SU.
            uint32_t talkgroup = 0U;                    //!< Affiliated local talkgroup (0 = none).
            bool registered = false;                    //!< True while the SU is registered behind the peer.
        };

        /**
         * @brief Initializes a new instance of the SuidRegistrationTable class.
         */
        SuidRegistrationTable();

        /**
         * @brief Registers a foreign SU behind a peer (moving it from any other peer).
         * @param suid Foreign SUID.
         * @param peerId Announcing peer ID.
         * @returns bool True if stored; false for peer 0 or an out-of-range SUID.
         */
        bool registerUnit(const roaming::SUID& suid, uint32_t peerId);
        /**
         * @brief Removes a foreign SU when it is registered behind the specified peer.
         * @param suid Foreign SUID.
         * @param peerId Announcing peer ID.
         * @returns bool True if removed; otherwise, false.
         */
        bool deregisterUnit(const roaming::SUID& suid, uint32_t peerId);
        /**
         * @brief Records a foreign SU's group affiliation behind a peer.
         * @param suid Foreign SUID.
         * @param peerId Announcing peer ID.
         * @param talkgroup Local talkgroup ID.
         * @returns bool True if stored; false for peer 0 or an out-of-range SUID.
         */
        bool affiliate(const roaming::SUID& suid, uint32_t peerId, uint32_t talkgroup);
        /**
         * @brief Clears a foreign SU's group affiliation when it is held by the specified peer.
         * @param suid Foreign SUID.
         * @param peerId Announcing peer ID.
         * @returns bool True if cleared; otherwise, false.
         */
        bool unaffiliate(const roaming::SUID& suid, uint32_t peerId);
        /**
         * @brief Replaces a peer's foreign registrations with a complete snapshot.
         * @param peerId Announcing peer ID.
         * @param regs Complete list of foreign SUIDs registered behind the peer.
         * @returns std::vector<roaming::SUID> SUIDs whose registration the snapshot removed.
         */
        std::vector<roaming::SUID> replacePeerRegistrations(uint32_t peerId, const std::vector<roaming::SUID>& regs);
        /**
         * @brief Replaces a peer's foreign affiliations with a complete snapshot.
         * @param peerId Announcing peer ID.
         * @param affs Complete list of foreign SUIDs and talkgroups behind the peer.
         */
        void replacePeerAffiliations(uint32_t peerId, const std::vector<roaming::SuidAnnouncement>& affs);
        /**
         * @brief Removes every foreign SU behind a peer.
         * @param peerId Peer ID.
         * @returns std::vector<roaming::SUID> Removed SUIDs.
         */
        std::vector<roaming::SUID> erasePeer(uint32_t peerId);
        /**
         * @brief Finds a foreign SU.
         * @param suid Foreign SUID.
         * @param[out] entry Entry when found.
         * @returns bool True if found; otherwise, false.
         */
        bool find(const roaming::SUID& suid, Entry& entry) const;
        /**
         * @brief Gets a copy of every entry.
         * @returns std::vector<Entry> Entries.
         */
        std::vector<Entry> snapshot() const;

    private:
        mutable std::mutex m_mutex;
        std::unordered_map<uint64_t, Entry> m_entries;
    };
} // namespace network

#endif // __SUID_REGISTRATION_TABLE_H__
