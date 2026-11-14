// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 Bryan Biedenkapp, N2PLL
 *
 */
/**
 * @file UnitRouteRegistry.h
 * @ingroup fne_network
 * @file UnitRouteRegistry.cpp
 * @ingroup fne_network
 */
#if !defined(__UNIT_ROUTE_REGISTRY_H__)
#define __UNIT_ROUTE_REGISTRY_H__

#include "fne/Defines.h"
#include "common/network/P25Roaming.h"

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace network
{
    // ---------------------------------------------------------------------------
    //  Structure Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Describes the current next-hop route to a registered subscriber unit.
     * @ingroup fne_network
     */
    struct HOST_SW_API UnitRoute {
        uint32_t unitId = 0U;        //!< Subscriber unit ID.
        uint32_t netId = 0U;         //!< Subscriber home WACN ID (own WACN ID for local radios).
        uint32_t sysId = 0U;         //!< Subscriber home System ID (own System ID for local radios).
        uint32_t peerId = 0U;        //!< Immediate next-hop peer ID.
        uint32_t ssrc = 0U;          //!< Advertised route origin or immediate peer SSRC.
        uint64_t lastSeen = 0U;      //!< Last update time in milliseconds.
        bool learned = false;        //!< True when learned from validated traffic rather than registration.
        bool roamed = false;         //!< True when stored by P25 roaming for a unit served through another link; only SUID
                                     //!<  lookups see it (bare Unit ID lookups ignore it until sub-project 3d).
        bool valid = false;          //!< True when the resolved route is current.
    };

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Stores timestamped subscriber-unit next-hop routes shared by all digital protocols, keyed by the
     *  packed 64-bit SUID (spec 2.6). Bare Unit ID methods address this system's own units and never see roaming
     *  routes (UnitRoute::roamed).
     * @ingroup fne_network
     */
    class HOST_SW_API UnitRouteRegistry {
    public:
        /**
         * @brief Initializes a unit-route registry.
         * @param lifetimeMs Lifetime of traffic-learned routes in milliseconds.
         */
        explicit UnitRouteRegistry(uint64_t lifetimeMs = 0U);

        /**
         * @brief Sets the lifetime of traffic-learned routes.
         * @param lifetimeMs Route lifetime in milliseconds.
         */
        void setLifetime(uint64_t lifetimeMs);
        /**
         * @brief Sets this system's WACN ID and System ID used by the bare Unit ID methods; existing own-system
         *  routes are re-keyed.
         * @param netId Own WACN ID (0 when the FNE has no P25 identity).
         * @param sysId Own System ID (0 when the FNE has no P25 identity).
         */
        void setOwnSystem(uint32_t netId, uint32_t sysId);
        /**
         * @brief Adds or refreshes a route for one of this system's units.
         * @param unitId Subscriber unit ID.
         * @param peerId Immediate next-hop peer ID.
         * @param ssrc Advertised route origin or immediate peer SSRC.
         * @param learned True for a traffic-learned route; false for an explicit registration.
         * @param nowMs Update time in milliseconds.
         * @returns bool True when a valid route was stored; otherwise, false.
         */
        bool update(uint32_t unitId, uint32_t peerId, uint32_t ssrc, bool learned, uint64_t nowMs);
        /**
         * @brief Adds or refreshes a route for a SUID.
         * @param suid Subscriber SUID.
         * @param peerId Immediate next-hop peer ID.
         * @param ssrc Advertised route origin or immediate peer SSRC.
         * @param learned True for a traffic-learned route; false for an explicit registration.
         * @param nowMs Update time in milliseconds.
         * @returns bool True when a valid route was stored; otherwise, false.
         */
        bool updateSuid(const roaming::SUID& suid, uint32_t peerId, uint32_t ssrc, bool learned, uint64_t nowMs);
        /**
         * @brief Adds or refreshes a P25 roaming route for a SUID served through another link (spec 2.6). The route
         *  is visible to resolveSuid() only; bare Unit ID lookups, erase() and replacePeer() ignore it.
         * @param suid Subscriber SUID.
         * @param peerId Immediate next-hop peer ID (the roaming link).
         * @param nowMs Update time in milliseconds.
         * @returns bool True when a valid route was stored; otherwise, false.
         */
        bool updateRoaming(const roaming::SUID& suid, uint32_t peerId, uint64_t nowMs);
        /**
         * @brief Replaces all explicit own-system routes learned through one peer (roaming routes are kept).
         * @param peerId Immediate next-hop peer ID.
         * @param unitIds Complete registration snapshot for the peer.
         * @param ssrc Advertised route origin or immediate peer SSRC.
         * @param nowMs Update time in milliseconds.
         */
        void replacePeer(uint32_t peerId, const std::vector<uint32_t>& unitIds, uint32_t ssrc, uint64_t nowMs);
        /**
         * @brief Removes an own-system route when it is currently owned by the specified peer (never a roaming route).
         * @param unitId Subscriber unit ID.
         * @param peerId Immediate next-hop peer ID.
         * @returns bool True when a route was removed; otherwise, false.
         */
        bool erase(uint32_t unitId, uint32_t peerId);
        /**
         * @brief Removes a SUID route when it is currently owned by the specified peer.
         * @param suid Subscriber SUID.
         * @param peerId Immediate next-hop peer ID.
         * @returns bool True when a route was removed; otherwise, false.
         */
        bool eraseSuid(const roaming::SUID& suid, uint32_t peerId);
        /**
         * @brief Removes every route using a peer as its next hop.
         * @param peerId Immediate next-hop peer ID.
         * @returns std::vector<uint32_t> Removed own-system subscriber unit IDs (roaming routes are removed but not reported).
         */
        std::vector<uint32_t> erasePeer(uint32_t peerId);
        /**
         * @brief Removes expired traffic-learned routes.
         * @param nowMs Current time in milliseconds.
         * @returns std::vector<UnitRoute> Routes removed by expiration.
         */
        std::vector<UnitRoute> expire(uint64_t nowMs);
        /**
         * @brief Resolves a current route for one of this system's units.
         * @param unitId Subscriber unit ID.
         * @param nowMs Current time in milliseconds.
         * @returns UnitRoute Current route, or an invalid route when unavailable or when the unit is only routed by
         *  P25 roaming.
         */
        UnitRoute resolve(uint32_t unitId, uint64_t nowMs) const;
        /**
         * @brief Resolves a current route for a SUID.
         * @param suid Subscriber SUID.
         * @param nowMs Current time in milliseconds.
         * @returns UnitRoute Current route, or an invalid route when unavailable.
         */
        UnitRoute resolveSuid(const roaming::SUID& suid, uint64_t nowMs) const;

    private:
        uint64_t m_lifetimeMs;
        uint32_t m_ownNetId;
        uint32_t m_ownSysId;
        mutable std::mutex m_mutex;
        std::unordered_map<uint64_t, UnitRoute> m_routes;

        /**
         * @brief Checks whether a traffic-learned route is stale.
         * @param route Route to check.
         * @param nowMs Current time in milliseconds.
         * @returns bool True when the route is stale; otherwise, false.
         */
        bool stale(const UnitRoute& route, uint64_t nowMs) const;
        /**
         * @brief Builds the own-system SUID for a bare Unit ID (caller holds m_mutex).
         * @param unitId Subscriber unit ID.
         * @returns roaming::SUID Own-system SUID.
         */
        roaming::SUID ownSuid(uint32_t unitId) const;
        /**
         * @brief Checks whether a route belongs to this system (caller holds m_mutex).
         * @param route Route to check.
         * @returns bool True for an own-system route; otherwise, false.
         */
        bool isOwn(const UnitRoute& route) const;
        /**
         * @brief Adds or refreshes a route (caller holds m_mutex).
         * @param suid Subscriber SUID.
         * @param peerId Immediate next-hop peer ID.
         * @param ssrc Advertised route origin or immediate peer SSRC.
         * @param learned True for a traffic-learned route.
         * @param roamed True for a P25 roaming route.
         * @param nowMs Update time in milliseconds.
         * @returns bool True when a valid route was stored; otherwise, false.
         */
        bool storeLocked(const roaming::SUID& suid, uint32_t peerId, uint32_t ssrc, bool learned, bool roamed, uint64_t nowMs);
        /**
         * @brief Removes a route owned by a peer (caller holds m_mutex).
         * @param key Packed SUID.
         * @param peerId Immediate next-hop peer ID.
         * @returns bool True when a route was removed; otherwise, false.
         */
        bool eraseLocked(uint64_t key, uint32_t peerId);
        /**
         * @brief Resolves a route (caller holds m_mutex).
         * @param key Packed SUID.
         * @param nowMs Current time in milliseconds.
         * @returns UnitRoute Current route, or an invalid route when unavailable.
         */
        UnitRoute resolveLocked(uint64_t key, uint64_t nowMs) const;
    };
} // namespace network

#endif // __UNIT_ROUTE_REGISTRY_H__
