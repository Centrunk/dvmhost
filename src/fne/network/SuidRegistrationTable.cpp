// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "fne/network/SuidRegistrationTable.h"

using namespace network;
using namespace network::roaming;

#include <unordered_set>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the SuidRegistrationTable class. */

SuidRegistrationTable::SuidRegistrationTable() :
    m_mutex(),
    m_entries()
{
    /* stub */
}

/* Registers a foreign SU behind a peer. */

bool SuidRegistrationTable::registerUnit(const SUID& suid, uint32_t peerId)
{
    if (peerId == 0U || !suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    Entry& entry = m_entries[suid.pack()];
    if (entry.peerId != peerId) {
        entry.talkgroup = 0U;
    }

    entry.suid = suid;
    entry.peerId = peerId;
    entry.registered = true;
    return true;
}

/* Removes a foreign SU when it is registered behind the specified peer. */

bool SuidRegistrationTable::deregisterUnit(const SUID& suid, uint32_t peerId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_entries.find(suid.pack());
    if (it == m_entries.end() || it->second.peerId != peerId) {
        return false;
    }

    m_entries.erase(it);
    return true;
}

/* Records a foreign SU's group affiliation behind a peer. */

bool SuidRegistrationTable::affiliate(const SUID& suid, uint32_t peerId, uint32_t talkgroup)
{
    if (peerId == 0U || !suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    Entry& entry = m_entries[suid.pack()];
    if (entry.peerId != 0U && entry.peerId != peerId) {
        entry.registered = false;
    }

    entry.suid = suid;
    entry.peerId = peerId;
    entry.talkgroup = talkgroup;
    return true;
}

/* Clears a foreign SU's group affiliation when it is held by the specified peer. */

bool SuidRegistrationTable::unaffiliate(const SUID& suid, uint32_t peerId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_entries.find(suid.pack());
    if (it == m_entries.end() || it->second.peerId != peerId) {
        return false;
    }

    it->second.talkgroup = 0U;
    if (!it->second.registered) {
        m_entries.erase(it);
    }

    return true;
}

/* Replaces a peer's foreign registrations with a complete snapshot. */

std::vector<SUID> SuidRegistrationTable::replacePeerRegistrations(uint32_t peerId, const std::vector<SUID>& regs)
{
    std::vector<SUID> removed;
    std::unordered_set<uint64_t> keep;
    for (const SUID& suid : regs) {
        keep.insert(suid.pack());
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        if (it->second.peerId == peerId && it->second.registered && keep.find(it->first) == keep.end()) {
            removed.push_back(it->second.suid);
            it->second.registered = false;
            if (it->second.talkgroup == 0U) {
                it = m_entries.erase(it);
                continue;
            }
        }

        ++it;
    }

    for (const SUID& suid : regs) {
        if (!suid.valid()) {
            continue;
        }

        Entry& entry = m_entries[suid.pack()];
        if (entry.peerId != peerId) {
            entry.talkgroup = 0U;
        }

        entry.suid = suid;
        entry.peerId = peerId;
        entry.registered = true;
    }

    return removed;
}

/* Replaces a peer's foreign affiliations with a complete snapshot. */

void SuidRegistrationTable::replacePeerAffiliations(uint32_t peerId, const std::vector<SuidAnnouncement>& affs)
{
    std::unordered_map<uint64_t, uint32_t> talkgroups;
    for (const SuidAnnouncement& aff : affs) {
        talkgroups[aff.suid.pack()] = aff.talkgroup;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        if (it->second.peerId == peerId && talkgroups.find(it->first) == talkgroups.end()) {
            it->second.talkgroup = 0U;
            if (!it->second.registered) {
                it = m_entries.erase(it);
                continue;
            }
        }

        ++it;
    }

    for (const SuidAnnouncement& aff : affs) {
        if (!aff.suid.valid()) {
            continue;
        }

        Entry& entry = m_entries[aff.suid.pack()];
        if (entry.peerId != 0U && entry.peerId != peerId) {
            entry.registered = false;
        }

        entry.suid = aff.suid;
        entry.peerId = peerId;
        entry.talkgroup = aff.talkgroup;
    }
}

/* Removes every foreign SU behind a peer. */

std::vector<SUID> SuidRegistrationTable::erasePeer(uint32_t peerId)
{
    std::vector<SUID> removed;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        if (it->second.peerId == peerId) {
            removed.push_back(it->second.suid);
            it = m_entries.erase(it);
        }
        else {
            ++it;
        }
    }

    return removed;
}

/* Finds a foreign SU. */

bool SuidRegistrationTable::find(const SUID& suid, Entry& entry) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_entries.find(suid.pack());
    if (it == m_entries.end()) {
        return false;
    }

    entry = it->second;
    return true;
}

/* Gets a copy of every entry. */

std::vector<SuidRegistrationTable::Entry> SuidRegistrationTable::snapshot() const
{
    std::vector<Entry> entries;
    std::lock_guard<std::mutex> lock(m_mutex);
    entries.reserve(m_entries.size());
    for (const auto& entry : m_entries) {
        entries.push_back(entry.second);
    }

    return entries;
}
