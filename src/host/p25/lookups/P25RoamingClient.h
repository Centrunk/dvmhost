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
 * @file P25RoamingClient.h
 * @ingroup host_lookups
 * @file P25RoamingClient.cpp
 * @ingroup host_lookups
 */
#if !defined(__P25_ROAMING_CLIENT_H__)
#define __P25_ROAMING_CLIENT_H__

#include "Defines.h"
#include "common/network/P25Roaming.h"

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <vector>

namespace p25
{
    namespace lookups
    {
        // ---------------------------------------------------------------------------
        //  Class Declaration
        // ---------------------------------------------------------------------------

        /**
         * @brief Implements the serving-side P25 roaming state of a dvmhost site (spec 4): Serving Registration
         *  transactions toward the home system, the RetryTime hold-off, refresh at 80 % of expires, Forced-query
         *  timers and link resynchronisation. It owns no sockets; Control supplies the callbacks.
         * @ingroup host_lookups
         */
        class HOST_SW_API P25RoamingClient {
        public:
            /**
             * @brief Result of a Serving Registration request.
             */
            enum class RequestResult : uint8_t {
                SENT,                                   //!< ROAM_SERVING_REG was sent toward the home.
                PENDING,                                //!< A request for the SUID is pending; nothing was sent.
                HELD_OFF,                               //!< A FAILED outcome is inside RetryTime; nothing was sent.
                NOT_CAPABLE                             //!< The FNE link did not negotiate P25 roaming, or the SUID or serving identity is out of range; nothing was sent.
            };

            /**
             * @brief Outcome of a Serving Registration.
             */
            enum class Outcome : uint8_t {
                SUCCESS,                                //!< The home answered success (see Profile::access).
                REJECTED,                               //!< The home answered a known failure code.
                FAILED                                  //!< Timeout, link loss or unknown result (local outcome, BACA 2.1.4.1.1).
            };

            /**
             * @brief Service profile the home returned (BACA 3.8.2.1, 3.8.2.15).
             * @ingroup host_lookups
             */
            struct Profile {
                uint8_t result = 0U;                    //!< Result code (network::roaming::RoamResult::E).
                uint8_t access = 0U;                    //!< Access (network::roaming::RoamAccess::E).
                bool inhibited = false;                 //!< Radio inhibited.
                uint32_t expires = 0U;                  //!< Home registration lifetime in seconds.
            };

            /**
             * @brief Initializes a new instance of the P25RoamingClient class.
             * @param homeTimeoutMs Time to wait for the home's Serving Registration response, in milliseconds.
             */
            explicit P25RoamingClient(uint32_t homeTimeoutMs = network::roaming::ROAM_DEFAULT_HOME_TIMEOUT_MS);
            /**
             * @brief Copy construction is disabled; the client owns a mutex and transaction state.
             * @param other Instance that would be copied.
             */
            P25RoamingClient(const P25RoamingClient& other) = delete;
            /**
             * @brief Copy assignment is disabled; the client owns a mutex and transaction state.
             * @param other Instance that would be copied.
             * @returns P25RoamingClient& Not applicable; the operator is deleted.
             */
            P25RoamingClient& operator=(const P25RoamingClient& other) = delete;

            /**
             * @brief Sets roamingHomeTimeout.
             * @param ms Timeout in milliseconds; 0 selects the default.
             */
            void setHomeTimeout(uint32_t ms);
            /**
             * @brief Gets roamingHomeTimeout.
             * @returns uint32_t Timeout in milliseconds.
             */
            uint32_t homeTimeout() const;

            /**
             * @brief Sets the callback that fills the serving RFSS identity and reports link capability.
             * @param provider Returns true when the FNE link negotiated P25 roaming.
             */
            void setContextProvider(std::function<bool(network::roaming::RfssIdentity&)>&& provider);
            /**
             * @brief Sets the callback that sends an encoded ROAMING message to the FNE.
             * @param sender Receives the sub-function, message and length.
             */
            void setSender(std::function<bool(uint8_t, const uint8_t*, uint32_t)>&& sender);
            /**
             * @brief Sets the callback that applies a Serving Registration outcome on air.
             * @param callback Receives the SUID, outcome, profile and on-air flag; returns true if the SU is admitted.
             */
            void setOutcomeCallback(std::function<bool(const network::roaming::SUID&, Outcome, const Profile&, bool)>&& callback);
            /**
             * @brief Sets the callback that releases an SU on Home Deregistration.
             * @param callback Receives the SUID and qualifier; returns true if the host held the SU.
             */
            void setHomeDeregCallback(std::function<bool(const network::roaming::SUID&, uint8_t)>&& callback);
            /**
             * @brief Sets the callback that sends U_REG_CMD to an SU's WUID (Forced query).
             * @param callback Receives the SUID; returns true if the SU has a WUID.
             */
            void setRegCmdCallback(std::function<bool(const network::roaming::SUID&)>&& callback);
            /**
             * @brief Sets the callback that releases an SU that did not answer a Forced query.
             * @param callback Receives the SUID.
             */
            void setForcedExpiryCallback(std::function<void(const network::roaming::SUID&)>&& callback);

            /**
             * @brief Requests Serving Registration for a roaming SU.
             * @param suid Roaming SUID.
             * @param confirmed True when triggered by a U_REG_REQ on air (presence Confirmed).
             * @returns RequestResult What was done.
             */
            RequestResult requestRegistration(const network::roaming::SUID& suid, bool confirmed);
            /**
             * @brief Ends a home-registered roamer's registration here and tells the home (spec 4.3).
             * @param suid Roaming SUID.
             * @returns bool True if ROAM_SERVING_DEREG was sent; false if the SU was not a roamer or the link is down.
             */
            bool servingDeregistration(const network::roaming::SUID& suid);
            /**
             * @brief Forgets a roamer without any network message.
             * @param suid Roaming SUID.
             */
            void forget(const network::roaming::SUID& suid);
            /**
             * @brief Gets whether an SU is registered here through its home.
             * @param suid Roaming SUID.
             * @returns bool True if held as a roamer; otherwise, false.
             */
            bool isRoamer(const network::roaming::SUID& suid) const;
            /**
             * @brief Gets whether a Serving Registration is pending.
             * @param suid Roaming SUID.
             * @returns bool True if pending; otherwise, false.
             */
            bool isPending(const network::roaming::SUID& suid) const;
            /**
             * @brief Gets whether a roamer's home granted emergency access only.
             * @param suid Roaming SUID.
             * @returns bool True if emergency access only; otherwise, false.
             */
            bool isEmergencyOnly(const network::roaming::SUID& suid) const;
            /**
             * @brief Gets the service profile the home returned for a roamer registered here.
             * @param suid Roaming SUID.
             * @param[out] profile Stored service profile when the SU is held.
             * @returns bool True if held as a roamer; otherwise, false.
             */
            bool roamerProfile(const network::roaming::SUID& suid, Profile& profile) const;
            /**
             * @brief Gets every roamer registered here through its home.
             * @returns std::vector<network::roaming::SUID> Roamer SUIDs.
             */
            std::vector<network::roaming::SUID> roamers() const;

            /**
             * @brief Processes a ROAMING message from the FNE.
             * @param subFunc ROAMING sub-function.
             * @param[in] data Message bytes.
             * @param length Message length in bytes.
             */
            void processMessage(uint8_t subFunc, const uint8_t* data, uint32_t length);
            /**
             * @brief Updates timers by the passed number of milliseconds.
             * @param ms Elapsed time in milliseconds.
             */
            void clock(uint32_t ms);

        private:
            /**
             * @brief Pending Serving Registration.
             * @ingroup host_lookups
             */
            struct Pending {
                network::roaming::SUID suid;            //!< Roaming SUID.
                uint32_t txnId = 0U;                    //!< Transaction ID.
                uint32_t elapsedMs = 0U;                //!< Time waited so far.
                bool onAir = false;                     //!< An SU request waits for an on-air answer.
            };

            /**
             * @brief Roamer registered here through its home.
             * @ingroup host_lookups
             */
            struct Roamer {
                network::roaming::SUID suid;            //!< Roaming SUID.
                Profile profile;                        //!< Service profile.
                uint32_t refreshMs = 0U;                //!< Time until the next timer refresh.
                uint32_t forcedMs = 0U;                 //!< Time left to answer a Forced query (0 = none).
            };

            /**
             * @brief RetryTime hold-off after a FAILED outcome, or the late-success marker left by a deregistration
             *  while the first registration was pending.
             * @ingroup host_lookups
             */
            struct HoldOff {
                uint32_t remainingMs = 0U;              //!< Time left.
                uint32_t txnId = 0U;                    //!< Transaction that failed or was abandoned.
                bool denied = false;                    //!< The SU is not served here; a late success sends one Serving Deregistration.
                bool deregistered = false;              //!< Armed by a deregistration (never holds off a new request).
            };

            /** @brief Deferred sends run after the mutex is released. */
            typedef std::vector<std::function<void()>> ActionList;

            mutable std::mutex m_mutex;
            uint32_t m_homeTimeoutMs;
            bool m_linkDown;                            //!< The link was seen not roaming capable; resync when it returns.
            std::map<uint64_t, Pending> m_pending;
            std::map<uint64_t, Roamer> m_roamers;
            std::map<uint64_t, HoldOff> m_holdOff;
            std::mt19937 m_random;
            std::function<bool(network::roaming::RfssIdentity&)> m_provider;
            std::function<bool(uint8_t, const uint8_t*, uint32_t)> m_sender;
            std::function<bool(const network::roaming::SUID&, Outcome, const Profile&, bool)> m_outcome;
            std::function<bool(const network::roaming::SUID&, uint8_t)> m_homeDereg;
            std::function<bool(const network::roaming::SUID&)> m_regCmd;
            std::function<void(const network::roaming::SUID&)> m_forcedExpiry;

            /**
             * @brief Fills the serving identity and reports link capability.
             * @param[out] serving Serving RFSS identity.
             * @returns bool True if the link negotiated roaming; otherwise, false.
             */
            bool context(network::roaming::RfssIdentity& serving) const;
            /**
             * @brief Generates a transaction ID (caller holds m_mutex).
             * @returns uint32_t Transaction ID.
             */
            uint32_t nextTxnId();
            /**
             * @brief Gets the refresh period for a lifetime (80 % of expires).
             * @param expires Lifetime in seconds.
             * @returns uint32_t Period in milliseconds.
             */
            static uint32_t refreshPeriodMs(uint32_t expires);
            /**
             * @brief Encodes a message and queues its send.
             * @param actions Action list.
             * @param msg Message.
             */
            void queueSend(ActionList& actions, const network::roaming::RoamingMessage& msg) const;
            /**
             * @brief Starts a Not Confirmed refresh for a roamer (caller holds m_mutex).
             * @param actions Action list.
             * @param roamer Roamer.
             * @param serving Serving RFSS identity.
             */
            void startRefresh(ActionList& actions, Roamer& roamer, const network::roaming::RfssIdentity& serving);
            /**
             * @brief Sends ROAM_SERVING_DEREG without changing roamer state.
             * @param suid Roaming SUID.
             * @returns bool True if sent; otherwise, false.
             */
            bool sendServingDereg(const network::roaming::SUID& suid);
            /**
             * @brief Delivers an outcome and updates roamer and hold-off state (no lock held).
             * @param suid Roaming SUID.
             * @param txnId Transaction ID.
             * @param outcome Outcome.
             * @param profile Service profile.
             * @param onAir An SU request waits for an on-air answer.
             */
            void completeOutcome(const network::roaming::SUID& suid, uint32_t txnId, Outcome outcome, const Profile& profile, bool onAir);
            /**
             * @brief Handles ROAM_SERVING_REG_RSP or a ROAM_GEN_RSP rejecting ROAM_SERVING_REG.
             * @param msg Decoded response.
             * @param general True for ROAM_GEN_RSP.
             */
            void handleRegResponse(const network::roaming::RoamingMessage& msg, bool general);
            /**
             * @brief Handles ROAM_HOME_DEREG.
             * @param msg Decoded request.
             */
            void handleHomeDereg(const network::roaming::RoamingMessage& msg);
            /**
             * @brief Handles ROAM_QUERY.
             * @param msg Decoded request.
             */
            void handleQuery(const network::roaming::RoamingMessage& msg);
            /**
             * @brief Runs deferred actions (no lock held).
             * @param actions Action list.
             */
            static void runActions(ActionList& actions);
        };
    } // namespace lookups
} // namespace p25

#endif // __P25_ROAMING_CLIENT_H__
