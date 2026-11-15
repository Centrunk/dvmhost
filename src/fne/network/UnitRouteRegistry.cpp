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
    m_mutex(),
    m_routes(),
    m_suidRoutes()
{
    /* stub */
}

/* Sets the lifetime of traffic-learned routes. */

void UnitRouteRegistry::setLifetime(uint64_t lifetimeMs)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lifetimeMs = lifetimeMs;
}

/* Adds or refreshes a route. */

bool UnitRouteRegistry::update(uint32_t unitId, uint32_t peerId, uint32_t ssrc, bool learned, uint64_t nowMs, bool p25Registered)
{
    if (unitId == 0U || peerId == 0U)
        return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_routes.find(unitId);
    if (it != m_routes.end() && !it->second.learned && learned) {
        if (it->second.peerId != peerId)
            return false;
        it->second.lastSeen = nowMs;
        return true;
    }

    UnitRoute& route = m_routes[unitId];
    route.unitId = unitId;
    route.peerId = peerId;
    route.ssrc = ssrc != 0U ? ssrc : peerId;
    route.lastSeen = nowMs;
    route.learned = learned;
    route.p25Registered = p25Registered && !learned;
    route.valid = true;
    return true;
}

/* Adds or refreshes an explicit route for a SUID served by a foreign system or roamed to another link. */

bool UnitRouteRegistry::updateSuid(const roaming::SUID& suid, uint32_t peerId, uint32_t ssrc, uint64_t nowMs)
{
    if (!suid.valid() || suid.unitId == 0U || peerId == 0U)
        return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    UnitRoute& route = m_suidRoutes[suid.pack()];
    route.unitId = suid.unitId;
    route.netId = suid.netId;
    route.sysId = suid.sysId;
    route.peerId = peerId;
    route.ssrc = ssrc != 0U ? ssrc : peerId;
    route.lastSeen = nowMs;
    route.valid = true;
    return true;
}

/* Replaces all explicit routes learned through one peer. */

void UnitRouteRegistry::replacePeer(uint32_t peerId, const std::vector<uint32_t>& unitIds, uint32_t ssrc, uint64_t nowMs)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_routes.begin(); it != m_routes.end();) {
        if (it->second.peerId == peerId && !it->second.learned &&
            std::find(unitIds.cbegin(), unitIds.cend(), it->first) == unitIds.cend()) {
            it = m_routes.erase(it);
        }
        else {
            ++it;
        }
    }

    for (uint32_t unitId : unitIds) {
        if (unitId == 0U)
            continue;
        UnitRoute& route = m_routes[unitId];

        // the snapshot carries no protocol, so it neither proves nor disproves a P25 registration already held by
        //  the same peer; any other listed route is untagged
        const bool keepP25 = route.valid && route.peerId == peerId && !route.learned && route.p25Registered;

        route.unitId = unitId;
        route.peerId = peerId;
        route.ssrc = ssrc != 0U ? ssrc : peerId;
        route.lastSeen = nowMs;
        route.learned = false;
        route.p25Registered = keepP25;
        route.valid = true;
    }
}

/* Removes a route when it is currently owned by the specified peer. */

bool UnitRouteRegistry::erase(uint32_t unitId, uint32_t peerId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_routes.find(unitId);
    if (it == m_routes.end() || it->second.peerId != peerId)
        return false;
    m_routes.erase(it);
    return true;
}

/* Removes a SUID route when it is currently owned by the specified peer. */

bool UnitRouteRegistry::eraseSuid(const roaming::SUID& suid, uint32_t peerId)
{
    if (!suid.valid())
        return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_suidRoutes.find(suid.pack());
    if (it == m_suidRoutes.end() || it->second.peerId != peerId)
        return false;
    m_suidRoutes.erase(it);
    return true;
}

/* Removes every route using a peer as its next hop. */

std::vector<uint32_t> UnitRouteRegistry::erasePeer(uint32_t peerId)
{
    std::vector<uint32_t> removed;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_routes.begin(); it != m_routes.end();) {
        if (it->second.peerId == peerId) {
            removed.push_back(it->first);
            it = m_routes.erase(it);
        }
        else {
            ++it;
        }
    }

    for (auto it = m_suidRoutes.begin(); it != m_suidRoutes.end();) {
        if (it->second.peerId == peerId) {
            it = m_suidRoutes.erase(it);
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

/* Resolves a current route for a subscriber unit. */

UnitRoute UnitRouteRegistry::resolve(uint32_t unitId, uint64_t nowMs) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_routes.find(unitId);
    if (it == m_routes.end() || stale(it->second, nowMs))
        return UnitRoute();
    return it->second;
}

/* Resolves the route stored for a SUID. */

UnitRoute UnitRouteRegistry::resolveSuid(const roaming::SUID& suid) const
{
    if (!suid.valid())
        return UnitRoute();

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_suidRoutes.find(suid.pack());
    if (it == m_suidRoutes.end())
        return UnitRoute();
    return it->second;
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Checks whether a traffic-learned route is stale. */

bool UnitRouteRegistry::stale(const UnitRoute& route, uint64_t nowMs) const
{
    return route.learned && m_lifetimeMs != 0U && nowMs >= route.lastSeen && nowMs - route.lastSeen >= m_lifetimeMs;
}
