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
 * @file RoamingConfig.h
 * @ingroup fne_network
 * @file RoamingConfig.cpp
 * @ingroup fne_network
 */
#if !defined(__FNE_ROAMING_CONFIG_H__)
#define __FNE_ROAMING_CONFIG_H__

#include "fne/Defines.h"
#include "common/json/json.h"
#include "common/network/P25Roaming.h"
#include "common/yaml/Yaml.h"

#include <cstdint>
#include <string>

namespace network
{
    /**
     * @brief Result of loading the FNE P25 roaming configuration.
     * @ingroup fne_network
     */
    namespace RoamingConfigLoad {
        /** @brief Load Result */
        enum E : uint8_t {
            OK = 0U,                                    //!< Loaded (identity set, or no identity configured)
            INVALID = 1U,                               //!< Partial, malformed or out-of-range identity; roaming disabled
            EXPIRES_TOO_SHORT = 2U,                     //!< p25RoamingExpires <= 14400; roaming disabled
            PROTECTED_WACN = 3U                         //!< p25NetId inside BEE00 - BEEFF; startup must fail
        };
    }

    /**
     * @brief Result of evaluating a peer's P25 identity at login.
     * @ingroup fne_network
     */
    namespace RoamingLogin {
        /** @brief Login Result */
        enum E : uint8_t {
            NOT_CAPABLE = 0U,                           //!< Accept the login without P25 roaming
            CAPABLE = 1U,                               //!< Accept the login with P25 roaming
            REJECT_MISMATCH = 2U,                       //!< Reject: host WACN ID or System ID differs from this system
            SAME_SYSTEM_FNE = 3U                        //!< Accept without P25 roaming: a downstream FNE offered this system's
                                                        //!<  own identity (exactly one FNE per system holds it, the home)
        };
    }

    // ---------------------------------------------------------------------------
    //  Class Declaration
    // ---------------------------------------------------------------------------

    /**
     * @brief Holds this FNE's P25 system identity and roaming parameters (spec 2.1, 7) and evaluates peer logins.
     * @ingroup fne_network
     */
    class HOST_SW_API RoamingConfig {
    public:
        /**
         * @brief Initializes a new instance of the RoamingConfig class (no identity, roaming disabled).
         */
        RoamingConfig();

        /**
         * @brief Loads system.p25NetId, system.p25SysId and system.p25RoamingExpires.
         * @param systemConf FNE system configuration node.
         * @returns RoamingConfigLoad::E Load result; roaming is enabled only on OK with both keys set.
         */
        RoamingConfigLoad::E load(yaml::Node& systemConf);
        /**
         * @brief Sets the identity directly (used by tests and harnesses); applies the same validation as load().
         * @param netId System WACN ID.
         * @param sysId System ID.
         * @param expires Home registration lifetime in seconds.
         * @returns bool True if roaming is enabled; otherwise, false.
         */
        bool set(uint32_t netId, uint32_t sysId, uint32_t expires);

        /**
         * @brief Gets whether this FNE has a P25 identity and negotiates roaming.
         * @returns bool True if enabled; otherwise, false.
         */
        bool enabled() const { return m_enabled; }
        /**
         * @brief Gets this system's WACN ID.
         * @returns uint32_t WACN ID, or 0 when disabled.
         */
        uint32_t netId() const { return m_netId; }
        /**
         * @brief Gets this system's System ID.
         * @returns uint32_t System ID, or 0 when disabled.
         */
        uint32_t sysId() const { return m_sysId; }
        /**
         * @brief Gets the home registration lifetime returned as expires.
         * @returns uint32_t Lifetime in seconds.
         */
        uint32_t expires() const { return m_expires; }

        /**
         * @brief Evaluates the p25Roaming object of an RPTC configuration (spec 2.2, 3.1).
         * @param peerConfig RPTC configuration JSON.
         * @param neighbor Flag indicating the peer is a downstream FNE (expected to be another system; one offering this
         *  system's identity is answered SAME_SYSTEM_FNE).
         * @param[out] peer Offered identity (zeroed when none was offered).
         * @returns RoamingLogin::E Login decision.
         */
        RoamingLogin::E evaluateLogin(const json::object& peerConfig, bool neighbor, roaming::RoamingPeerConfig& peer) const;
        /**
         * @brief Builds the RPTC ACK payload (bit 6 and identity when enabled).
         * @param[out] payload Output buffer.
         * @param payloadLen Output buffer length in bytes.
         * @returns uint32_t Payload length (1 or 6), or 0 on a short buffer.
         */
        uint32_t buildConfigAck(uint8_t* payload, uint32_t payloadLen) const;

        /**
         * @brief Parses a hexadecimal identity string (optional 0x prefix, hex digits only).
         * @param text Text to parse.
         * @param max Largest accepted value.
         * @param[out] value Parsed value; written only on success.
         * @returns bool True if the text is a clean hexadecimal value of at most max; otherwise, false.
         */
        static bool parseHex(const std::string& text, uint32_t max, uint32_t& value);

    private:
        bool m_enabled;
        uint32_t m_netId;
        uint32_t m_sysId;
        uint32_t m_expires;
    };
} // namespace network

#endif // __FNE_ROAMING_CONFIG_H__
