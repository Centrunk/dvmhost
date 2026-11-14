// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 Bryan Biedenkapp, N2PLL
 *
 */
#include "fne/network/UnitRouteRegistry.h"

using namespace network;

#include <algorithm>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a unit-route registry. */

UnitRouteRegistry::UnitRouteRegistry(uint64_t lifetimeMs) :
    m_lifetimeMs(lifetimeMs),
    m_ownNetId(0U),
    m_ownSysId(0U),
    m_mutex(),
    m_routes()
{
    /* stub */
}

/* Sets the lifetime of traffic-learned routes. */

void UnitRouteRegistry::setLifetime(uint64_t lifetimeMs)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lifetimeMs = lifetimeMs;
}

/* Sets this system's WACN ID and System ID used by the bare Unit ID methods. */

void UnitRouteRegistry::setOwnSystem(uint32_t netId, uint32_t sysId)
{
    // SUID::pack() masks silently, so an out-of-range identity is never stored
    if (!roaming::SUID::validSystem(netId, sysId)) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (netId == m_ownNetId && sysId == m_ownSysId) {
        return;
    }

    // re-key the own-system routes so bare Unit ID lookups keep resolving
    std::unordered_map<uint64_t, UnitRoute> rekeyed;
    rekeyed.reserve(m_routes.size());
    for (const auto& entry : m_routes) {
        UnitRoute route = entry.second;
        if (isOwn(route)) {
            route.netId = netId;
            route.sysId = sysId;
        }

        roaming::SUID suid;
        suid.netId = route.netId;
        suid.sysId = route.sysId;
        suid.unitId = route.unitId;
        rekeyed[suid.pack()] = route;
    }

    m_routes.swap(rekeyed);
    m_ownNetId = netId;
    m_ownSysId = sysId;
}

/* Adds or refreshes a route for one of this system's units. */

bool UnitRouteRegistry::update(uint32_t unitId, uint32_t peerId, uint32_t ssrc, bool learned, uint64_t nowMs)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const roaming::SUID suid = ownSuid(unitId);
    if (!suid.valid()) {
        return false;
    }

    return storeLocked(suid, peerId, ssrc, learned, nowMs);
}

/* Adds or refreshes a route for a SUID. */

bool UnitRouteRegistry::updateSuid(const roaming::SUID& suid, uint32_t peerId, uint32_t ssrc, bool learned, uint64_t nowMs)
{
    if (!suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    return storeLocked(suid, peerId, ssrc, learned, nowMs);
}

/* Replaces all explicit own-system routes learned through one peer. */

void UnitRouteRegistry::replacePeer(uint32_t peerId, const std::vector<uint32_t>& unitIds, uint32_t ssrc, uint64_t nowMs)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_routes.begin(); it != m_routes.end();) {
        if (isOwn(it->second) && it->second.peerId == peerId && !it->second.learned &&
            std::find(unitIds.cbegin(), unitIds.cend(), it->second.unitId) == unitIds.cend()) {
            it = m_routes.erase(it);
        }
        else {
            ++it;
        }
    }

    for (uint32_t unitId : unitIds) {
        const roaming::SUID suid = ownSuid(unitId);
        if (unitId == 0U || !suid.valid())
            continue;

        UnitRoute& route = m_routes[suid.pack()];
        route.unitId = unitId;
        route.netId = suid.netId;
        route.sysId = suid.sysId;
        route.peerId = peerId;
        route.ssrc = ssrc != 0U ? ssrc : peerId;
        route.lastSeen = nowMs;
        route.learned = false;
        route.valid = true;
    }
}

/* Removes an own-system route when it is currently owned by the specified peer. */

bool UnitRouteRegistry::erase(uint32_t unitId, uint32_t peerId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const roaming::SUID suid = ownSuid(unitId);
    if (!suid.valid()) {
        return false;
    }

    return eraseLocked(suid.pack(), peerId);
}

/* Removes a SUID route when it is currently owned by the specified peer. */

bool UnitRouteRegistry::eraseSuid(const roaming::SUID& suid, uint32_t peerId)
{
    if (!suid.valid()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    return eraseLocked(suid.pack(), peerId);
}

/* Removes every route using a peer as its next hop. */

std::vector<uint32_t> UnitRouteRegistry::erasePeer(uint32_t peerId)
{
    std::vector<uint32_t> removed;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_routes.begin(); it != m_routes.end();) {
        if (it->second.peerId == peerId) {
            if (isOwn(it->second)) {
                removed.push_back(it->second.unitId);
            }

            it = m_routes.erase(it);
        }
        else {
            ++it;
        }
    }
    return removed;
}

/* Removes expired traffic-learned routes. */

std::vector<UnitRoute> UnitRouteRegistry::expire(uint64_t nowMs)
{
    std::vector<UnitRoute> expired;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_routes.begin(); it != m_routes.end();) {
        if (stale(it->second, nowMs)) {
            expired.push_back(it->second);
            it = m_routes.erase(it);
        }
        else {
            ++it;
        }
    }
    return expired;
}

/* Resolves a current route for one of this system's units. */

UnitRoute UnitRouteRegistry::resolve(uint32_t unitId, uint64_t nowMs) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const roaming::SUID suid = ownSuid(unitId);
    if (!suid.valid()) {
        return UnitRoute();
    }

    return resolveLocked(suid.pack(), nowMs);
}

/* Resolves a current route for a SUID. */

UnitRoute UnitRouteRegistry::resolveSuid(const roaming::SUID& suid, uint64_t nowMs) const
{
    if (!suid.valid()) {
        return UnitRoute();
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    return resolveLocked(suid.pack(), nowMs);
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Checks whether a traffic-learned route is stale. */

bool UnitRouteRegistry::stale(const UnitRoute& route, uint64_t nowMs) const
{
    return route.learned && m_lifetimeMs != 0U && nowMs >= route.lastSeen && nowMs - route.lastSeen >= m_lifetimeMs;
}

/* Builds the own-system SUID for a bare Unit ID. */

roaming::SUID UnitRouteRegistry::ownSuid(uint32_t unitId) const
{
    roaming::SUID suid;
    suid.netId = m_ownNetId;
    suid.sysId = m_ownSysId;
    suid.unitId = unitId;
    return suid;
}

/* Checks whether a route belongs to this system. */

bool UnitRouteRegistry::isOwn(const UnitRoute& route) const
{
    return route.netId == m_ownNetId && route.sysId == m_ownSysId;
}

/* Adds or refreshes a route. */

bool UnitRouteRegistry::storeLocked(const roaming::SUID& suid, uint32_t peerId, uint32_t ssrc, bool learned, uint64_t nowMs)
{
    if (suid.unitId == 0U || peerId == 0U)
        return false;

    const uint64_t key = suid.pack();
    auto it = m_routes.find(key);
    if (it != m_routes.end() && !it->second.learned && learned) {
        if (it->second.peerId != peerId)
            return false;
        it->second.lastSeen = nowMs;
        return true;
    }

    UnitRoute& route = m_routes[key];
    route.unitId = suid.unitId;
    route.netId = suid.netId;
    route.sysId = suid.sysId;
    route.peerId = peerId;
    route.ssrc = ssrc != 0U ? ssrc : peerId;
    route.lastSeen = nowMs;
    route.learned = learned;
    route.valid = true;
    return true;
}

/* Removes a route owned by a peer. */

bool UnitRouteRegistry::eraseLocked(uint64_t key, uint32_t peerId)
{
    auto it = m_routes.find(key);
    if (it == m_routes.end() || it->second.peerId != peerId)
        return false;
    m_routes.erase(it);
    return true;
}

/* Resolves a route. */

UnitRoute UnitRouteRegistry::resolveLocked(uint64_t key, uint64_t nowMs) const
{
    auto it = m_routes.find(key);
    if (it == m_routes.end() || stale(it->second, nowMs))
        return UnitRoute();
    return it->second;
}
