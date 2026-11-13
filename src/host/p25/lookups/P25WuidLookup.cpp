// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Modem Host Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "common/p25/P25Defines.h"
#include "p25/lookups/P25WuidLookup.h"

using namespace p25;
using namespace p25::defines;
using namespace p25::lookups;

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the P25WuidLookup class. */

P25WuidLookup::P25WuidLookup() :
    m_mutex(),
    m_start(0U),
    m_end(0U),
    m_bySuid(),
    m_byWuid()
{
    /* stub */
}

/* Validates a WUID pool range. */

bool P25WuidLookup::validRange(uint32_t start, uint32_t end)
{
    // $000000 is "No one" (TIA-102.BAAC-C); WUID_FNE and above are reserved special WUIDs
    return (start > 0U) && (start <= end) && (end < WUID_FNE);
}

/* Configures the WUID pool and clears all assignments. */

bool P25WuidLookup::setPool(uint32_t start, uint32_t end)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_bySuid.clear();
    m_byWuid.clear();

    if (!validRange(start, end)) {
        m_start = 0U;
        m_end = 0U;
        return false;
    }

    m_start = start;
    m_end = end;
    return true;
}

/* Removes the pool and all assignments. */

void P25WuidLookup::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_bySuid.clear();
    m_byWuid.clear();
    m_start = 0U;
    m_end = 0U;
}

/* Gets whether a WUID pool is configured. */

bool P25WuidLookup::enabled() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_start != 0U;
}

/* Gets the first WUID of the pool. */

uint32_t P25WuidLookup::poolStart() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_start;
}

/* Gets the last WUID of the pool. */

uint32_t P25WuidLookup::poolEnd() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_end;
}

/* Allocates a WUID for a roaming SU. */

uint32_t P25WuidLookup::allocate(const SUID& suid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_start == 0U) {
        return 0U;
    }

    // re-registration retains the existing WUID
    auto existing = m_bySuid.find(key(suid));
    if (existing != m_bySuid.end()) {
        return existing->second;
    }

    // walk the ordered assignments for the lowest gap in the pool
    uint32_t candidate = m_start;
    for (const auto& entry : m_byWuid) {
        if (entry.first == candidate) {
            candidate++;
        }
        else if (entry.first > candidate) {
            break;
        }
    }

    if (candidate > m_end) {
        return 0U;
    }

    m_bySuid[key(suid)] = candidate;
    m_byWuid[candidate] = suid;
    return candidate;
}

/* Releases an assigned WUID. */

bool P25WuidLookup::release(uint32_t wuid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_byWuid.find(wuid);
    if (it == m_byWuid.end()) {
        return false;
    }

    m_bySuid.erase(key(it->second));
    m_byWuid.erase(it);
    return true;
}

/* Finds the WUID assigned to an SUID. */

bool P25WuidLookup::findBySuid(const SUID& suid, uint32_t& wuid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_bySuid.find(key(suid));
    if (it == m_bySuid.end()) {
        return false;
    }

    wuid = it->second;
    return true;
}

/* Finds the SUID assigned to a WUID. */

bool P25WuidLookup::findByWuid(uint32_t wuid, SUID& suid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_byWuid.find(wuid);
    if (it == m_byWuid.end()) {
        return false;
    }

    suid = it->second;
    return true;
}

/* Determines whether a WUID lies within the configured pool. */

bool P25WuidLookup::isPoolWuid(uint32_t wuid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (m_start != 0U) && (wuid >= m_start) && (wuid <= m_end);
}

/* Gets the number of assigned WUIDs. */

uint32_t P25WuidLookup::count() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (uint32_t)m_byWuid.size();
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Packs an SUID into a 56-bit map key. */

uint64_t P25WuidLookup::key(const SUID& suid)
{
    return ((uint64_t)(suid.netId & 0xFFFFFU) << 36) +
        ((uint64_t)(suid.sysId & 0xFFFU) << 24) +
        (uint64_t)(suid.unitId & 0xFFFFFFU);
}
