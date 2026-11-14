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
 * @file RoamingService.h
 * @ingroup fne_network
 * @file RoamingService.cpp
 * @ingroup fne_network
 */
#if !defined(__ROAMING_SERVICE_H__)
#define __ROAMING_SERVICE_H__

#include "fne/Defines.h"
#include "common/network/P25Roaming.h"

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <unordered_map>
#include <utility>
#include <vector>

namespace network
{
    // ---------------------------------------------------------------------------
    //  Structure Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Identifies one FNE link that may carry P25 ROAMING messages.
     * @ingroup fne_network
     */
    struct HOST_SW_API RoamingLink {
        uint32_t peerId = 0U;                           //!< Downstream peer ID, or the upstream PeerNetwork's own peer ID.
        bool upstream = false;                          //!< True for an upstream master link (PeerNetwork).

        /**
         * @brief Checks whether the link names a peer.
         * @returns bool True if the peer ID is non-zero; otherwise, false.
         */
        bool valid() const { return peerId != 0U; }
        /**
         * @brief Compares two links.
         * @param other Link to compare.
         * @returns bool True if both fields are equal; otherwise, false.
         */
        bool operator==(const RoamingLink& other) const { return peerId == other.peerId && upstream == other.upstream; }
        /**
         * @brief Compares two links.
         * @param other Link to compare.
         * @returns bool True if any field differs; otherwise, false.
         */
        bool operator!=(const RoamingLink& other) const { return !(*this == other); }
        /**
         * @brief Packs the link into a map key.
         * @returns uint64_t (upstream << 32) | peerId.
         */
        uint64_t key() const { return (upstream ? 0x100000000ULL : 0ULL) | (uint64_t)peerId; }
    };

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Interface through which the RoamingService reaches FNE networking and lookup state.
     * @ingroup fne_network
     */
    class HOST_SW_API RoamingServiceHost {
    public:
        /**
         * @brief Finalizes a instance of the RoamingServiceHost class.
         */
        virtual ~RoamingServiceHost() = default;

        /**
         * @brief Sends an encoded ROAMING message on a link.
         * @param link Destination link.
         * @param subFunc ROAMING sub-function.
         * @param[in] data Encoded message.
         * @param length Message length in bytes.
         * @returns bool True if sent; otherwise, false.
         */
        virtual bool sendRoaming(const RoamingLink& link, uint8_t subFunc, const uint8_t* data, uint32_t length) = 0;
        /**
         * @brief Checks the home RID ACL (BACA 5.5 Gen Req 3).
         * @param unitId Home Unit ID.
         * @returns bool True if the unit is in the RID ACL and enabled; otherwise, false.
         */
        virtual bool isHomeUnitAuthorized(uint32_t unitId) = 0;
        /**
         * @brief Finds the home site (host peer) where a home unit is registered.
         * @param unitId Home Unit ID.
         * @returns uint32_t Host peer ID, or 0 when not registered on a home site.
         */
        virtual uint32_t findLocalUnitPeer(uint32_t unitId) = 0;
        /**
         * @brief Removes a home unit's registration at a home site.
         * @param peerId Host peer ID.
         * @param unitId Home Unit ID.
         */
        virtual void removeLocalUnitRegistration(uint32_t peerId, uint32_t unitId) = 0;
        /**
         * @brief Points the unit route for a SUID at a link.
         * @param suid Subscriber SUID.
         * @param link Next-hop link.
         */
        virtual void setUnitRoute(const roaming::SUID& suid, const RoamingLink& link) = 0;
        /**
         * @brief Removes the unit route for a SUID when it uses the link.
         * @param suid Subscriber SUID.
         * @param link Next-hop link.
         */
        virtual void eraseUnitRoute(const roaming::SUID& suid, const RoamingLink& link) = 0;
    };

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Implements the FNE side of P25 unit mobility (TIA-102.BACA-B Home and Serving RFSS functions carried
     *  over DVM ROAMING messages, spec 3.5 and 4): routing, transactions, home location and served-roamer tables.
     * @ingroup fne_network
     */
    class HOST_SW_API RoamingService {
    public:
        /**
         * @brief Home location record of a home SU served elsewhere (BACA 5.5.1).
         * @ingroup fne_network
         */
        struct HomeRecord {
            roaming::SUID suid;                         //!< Home SU.
            roaming::RfssIdentity serving;              //!< Serving RFSS identity.
            RoamingLink link;                           //!< Link toward the serving RFSS.
            uint64_t expiresAtMs = 0U;                  //!< Record expiry time in milliseconds.
            uint32_t lastTxnId = 0U;                    //!< Transaction ID of the registration that created or refreshed the record.
        };

        /**
         * @brief Served-roamer record for a roamer registered behind this FNE (spec 4.1 step 6).
         * @ingroup fne_network
         */
        struct ServingRecord {
            roaming::SUID suid;                         //!< Roaming SU.
            RoamingLink link;                           //!< Link toward the serving host.
        };

        /**
         * @brief Initializes a new instance of the RoamingService class.
         * @param host Network and lookup adapter (not owned; must outlive the service).
         */
        explicit RoamingService(RoamingServiceHost* host);
        /**
         * @brief Copy construction is disabled; the service owns a mutex and live transaction state.
         * @param other Service that would be copied.
         */
        RoamingService(const RoamingService& other) = delete;
        /**
         * @brief Copy assignment is disabled; the service owns a mutex and live transaction state.
         * @param other Service that would be copied.
         * @returns RoamingService& This instance.
         */
        RoamingService& operator=(const RoamingService& other) = delete;

        /**
         * @brief Sets this FNE's system identity; a zero WACN ID or System ID disables the service.
         * @param netId WACN ID.
         * @param sysId System ID.
         * @param expires Home registration lifetime in seconds.
         */
        void setIdentity(uint32_t netId, uint32_t sysId, uint32_t expires);
        /**
         * @brief Gets whether the service has a system identity.
         * @returns bool True if enabled; otherwise, false.
         */
        bool enabled() const;
        /**
         * @brief Records a link that completed login. An FNE link carrying this system's own identity is recorded as
         *  not roaming capable (exactly one FNE per system holds the identity).
         * @param link Link.
         * @param capable Flag indicating P25 roaming was negotiated on the link.
         * @param fne Flag indicating the far end is an FNE (another system) rather than a host.
         * @param netId Far-end WACN ID.
         * @param sysId Far-end System ID.
         */
        void linkUp(const RoamingLink& link, bool capable, bool fne, uint32_t netId, uint32_t sysId);
        /**
         * @brief Removes a link; its pending transactions complete as FAILED and its served records are dropped.
         * @param link Link.
         */
        void linkDown(const RoamingLink& link);
        /**
         * @brief Gets whether a link negotiated P25 roaming.
         * @param link Link.
         * @returns bool True if capable; otherwise, false.
         */
        bool isLinkCapable(const RoamingLink& link) const;
        /**
         * @brief Processes one ROAMING message received on a link.
         * @param ingress Link the message arrived on.
         * @param subFunc ROAMING sub-function.
         * @param[in] data Message bytes.
         * @param length Message length in bytes.
         * @param nowMs Current time in milliseconds.
         */
        void process(const RoamingLink& ingress, uint8_t subFunc, const uint8_t* data, uint32_t length, uint64_t nowMs);
        /**
         * @brief Expires forwarded transactions and home records.
         * @param nowMs Current time in milliseconds.
         */
        void clock(uint64_t nowMs);
        /**
         * @brief Sends Non-Roamed Home Deregistration for home records whose unit is no longer authorized (spec 4.4).
         * @param nowMs Current time in milliseconds.
         */
        void revalidateHomeRecords(uint64_t nowMs);
        /**
         * @brief Handles a home SU registering on one of this system's own sites: the previous serving RFSS is
         *  deregistered (Roamed; BACA 5.1).
         * @param unitId Home Unit ID.
         * @param nowMs Current time in milliseconds.
         */
        void localRegistration(uint32_t unitId, uint64_t nowMs);
        /**
         * @brief Sends a Forced query to the serving RFSS of a home SU (operator request, spec 4.5).
         * @param suid Home SUID.
         * @param nowMs Current time in milliseconds.
         * @returns bool True if sent; false if no home record exists.
         */
        bool forcedQuery(const roaming::SUID& suid, uint64_t nowMs);
        /**
         * @brief Gets a copy of the home location table.
         * @returns std::vector<HomeRecord> Home records.
         */
        std::vector<HomeRecord> homeRecords() const;
        /**
         * @brief Gets a copy of the served-roamer table.
         * @returns std::vector<ServingRecord> Served records.
         */
        std::vector<ServingRecord> servingRecords() const;
        /**
         * @brief Gets the number of open transactions.
         * @returns size_t Pending transaction count.
         */
        size_t pendingCount() const;

    private:
        /**
         * @brief State of one link.
         * @ingroup fne_network
         */
        struct LinkState {
            RoamingLink link;                           //!< Link.
            bool capable = false;                       //!< P25 roaming negotiated.
            bool fne = false;                           //!< Far end is an FNE.
            uint32_t netId = 0U;                        //!< Far-end WACN ID.
            uint32_t sysId = 0U;                        //!< Far-end System ID.
        };

        /**
         * @brief Open transaction, keyed by (egress link key, transaction ID).
         * @ingroup fne_network
         */
        struct Pending {
            RoamingLink ingress;                        //!< Link to relay the response to (invalid when originated here).
            uint8_t subFunc = 0U;                       //!< Request sub-function.
            uint64_t suid = 0U;                         //!< Packed subject SUID.
            uint64_t startedMs = 0U;                    //!< Time the request was sent.
        };

        /** @brief Deferred sends and host updates run after the service lock is released. */
        typedef std::vector<std::function<void()>> ActionList;

        RoamingServiceHost* m_host;
        mutable std::mutex m_mutex;
        uint32_t m_netId;
        uint32_t m_sysId;
        uint32_t m_expires;
        std::unordered_map<uint64_t, LinkState> m_links;
        std::unordered_map<uint32_t, RoamingLink> m_systems;
        RoamingLink m_upstreamDefault;
        std::unordered_map<uint64_t, HomeRecord> m_home;
        std::unordered_map<uint64_t, ServingRecord> m_serving;
        std::map<std::pair<uint64_t, uint32_t>, Pending> m_pending;
        std::mt19937 m_random;

        /**
         * @brief Checks a WACN ID and System ID against this system (caller holds m_mutex).
         * @param netId WACN ID.
         * @param sysId System ID.
         * @returns bool True if they name this system; otherwise, false.
         */
        bool isOwnSystem(uint32_t netId, uint32_t sysId) const;
        /**
         * @brief Checks whether a link's far end is an FNE (caller holds m_mutex).
         * @param link Link.
         * @returns bool True for an FNE link; otherwise, false.
         */
        bool linkIsFne(const RoamingLink& link) const;
        /**
         * @brief Checks whether a link negotiated roaming (caller holds m_mutex).
         * @param link Link.
         * @returns bool True if capable; otherwise, false.
         */
        bool linkCapableLocked(const RoamingLink& link) const;
        /**
         * @brief Policy check: may this serving system serve the SU (BACA 2.1.3.1.1)? Every roaming-capable peer
         *  system is permitted in sub-project 3b; later policy restricts it here.
         * @param serving Serving RFSS identity.
         * @param ingress Link the request arrived on.
         * @returns bool True if permitted; otherwise, false.
         */
        bool isServingPermitted(const roaming::RfssIdentity& serving, const RoamingLink& ingress) const;
        /**
         * @brief Chooses a new upstream default among capable upstream links (caller holds m_mutex).
         */
        void selectUpstreamDefault();
        /**
         * @brief Generates a transaction ID for a request originated here that is not already open toward the link
         *  (caller holds m_mutex).
         * @param link Destination link.
         * @returns uint32_t Transaction ID.
         */
        uint32_t nextTxnId(const RoamingLink& link);
        /**
         * @brief Encodes a message and queues its send.
         * @param actions Action list.
         * @param link Destination link.
         * @param msg Message.
         */
        void queueSend(ActionList& actions, const RoamingLink& link, const roaming::RoamingMessage& msg) const;
        /**
         * @brief Queues the response to a request with a result (hop count reset, transaction ID echoed).
         * @param actions Action list.
         * @param link Destination link.
         * @param request Request being answered.
         * @param result Result code.
         */
        void queueReply(ActionList& actions, const RoamingLink& link, const roaming::RoamingMessage& request, uint8_t result) const;
        /**
         * @brief Builds the home's success response to a Serving Registration (caller holds m_mutex).
         * @param request Serving Registration.
         * @returns roaming::RoamingMessage Response.
         */
        roaming::RoamingMessage successResponse(const roaming::RoamingMessage& request) const;
        /**
         * @brief Dispatches a decoded request (caller holds m_mutex).
         * @param actions Action list.
         * @param ingress Ingress link.
         * @param msg Request.
         * @param nowMs Current time in milliseconds.
         * @param authorized Home RID ACL result (SERVING_REG for this system only).
         * @param localPeer Home site holding the unit (SERVING_REG for this system only).
         */
        void handleRequest(ActionList& actions, const RoamingLink& ingress, const roaming::RoamingMessage& msg, uint64_t nowMs,
            bool authorized, uint32_t localPeer);
        /**
         * @brief Home handling of a Serving Registration (caller holds m_mutex). A previous serving RFSS behind a
         *  different link receives a Roamed Home Deregistration from the home; one behind the same link is
         *  deregistered by the downstream FNE whose served-roamer record changes link (see handleResponse).
         * @param actions Action list.
         * @param ingress Ingress link.
         * @param msg Request.
         * @param nowMs Current time in milliseconds.
         * @param authorized Home RID ACL result.
         * @param localPeer Home site holding the unit, or 0.
         */
        void handleHomeServingReg(ActionList& actions, const RoamingLink& ingress, const roaming::RoamingMessage& msg, uint64_t nowMs,
            bool authorized, uint32_t localPeer);
        /**
         * @brief Home handling of a Serving Deregistration (caller holds m_mutex).
         * @param actions Action list.
         * @param ingress Ingress link.
         * @param msg Request.
         */
        void handleHomeServingDereg(ActionList& actions, const RoamingLink& ingress, const roaming::RoamingMessage& msg);
        /**
         * @brief Forwards a request toward the SU's home system (caller holds m_mutex).
         * @param actions Action list.
         * @param ingress Ingress link.
         * @param msg Request.
         * @param nowMs Current time in milliseconds.
         */
        void forwardTowardHome(ActionList& actions, const RoamingLink& ingress, const roaming::RoamingMessage& msg, uint64_t nowMs);
        /**
         * @brief Forwards a request toward the SU's serving host (caller holds m_mutex).
         * @param actions Action list.
         * @param ingress Ingress link.
         * @param msg Request.
         * @param nowMs Current time in milliseconds.
         */
        void forwardTowardServing(ActionList& actions, const RoamingLink& ingress, const roaming::RoamingMessage& msg, uint64_t nowMs);
        /**
         * @brief Forwards a request on an egress link and opens a transaction (caller holds m_mutex).
         * @param actions Action list.
         * @param ingress Ingress link.
         * @param egress Egress link.
         * @param msg Request.
         * @param nowMs Current time in milliseconds.
         */
        void forward(ActionList& actions, const RoamingLink& ingress, const RoamingLink& egress, const roaming::RoamingMessage& msg, uint64_t nowMs);
        /**
         * @brief Sends a Home Deregistration originated here and opens its transaction (caller holds m_mutex).
         * @param actions Action list.
         * @param link Destination link.
         * @param suid Home SUID.
         * @param qualifier Roamed or Non-Roamed.
         * @param nowMs Current time in milliseconds.
         */
        void sendHomeDereg(ActionList& actions, const RoamingLink& link, const roaming::SUID& suid, uint8_t qualifier, uint64_t nowMs);
        /**
         * @brief Matches and relays (or consumes) a response (caller holds m_mutex). Relaying a successful Serving
         *  Registration Response moves the served-roamer record to the relay link; when the record was on a different
         *  link of this FNE, this FNE sends the previous serving side a Roamed Home Deregistration (BACA 5.1).
         * @param actions Action list.
         * @param from Link the response arrived on.
         * @param msg Response.
         * @param nowMs Current time in milliseconds.
         */
        void handleResponse(ActionList& actions, const RoamingLink& from, const roaming::RoamingMessage& msg, uint64_t nowMs);
        /**
         * @brief Runs deferred actions (no lock held).
         * @param actions Action list.
         */
        static void runActions(ActionList& actions);
        /**
         * @brief Gets a log name for a link direction.
         * @param link Link.
         * @returns const char* "UPSTREAM" or "PEER".
         */
        static const char* linkName(const RoamingLink& link);
    };
} // namespace network

#endif // __ROAMING_SERVICE_H__
