// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "network/P25Roaming.h"

using namespace network;
using namespace network::roaming;

#include <cstring>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Packs the SUID into its 64-bit table key. */

uint64_t SUID::pack() const
{
    return ((uint64_t)(netId & ROAM_MAX_WACN) << 36) | ((uint64_t)(sysId & ROAM_MAX_SYSID) << 24) |
        (uint64_t)(unitId & ROAM_MAX_UNIT_ID);
}

/* Unpacks a 64-bit SUID table key. */

SUID SUID::unpack(uint64_t key)
{
    SUID suid;
    suid.netId = (uint32_t)((key >> 36) & ROAM_MAX_WACN);
    suid.sysId = (uint32_t)((key >> 24) & ROAM_MAX_SYSID);
    suid.unitId = (uint32_t)(key & ROAM_MAX_UNIT_ID);
    return suid;
}

/* Checks the WACN ID, System ID and Unit ID ranges. */

bool SUID::valid() const
{
    return validSystem(netId, sysId) && unitId <= ROAM_MAX_UNIT_ID;
}

/* Compares two SUIDs. */

bool SUID::operator==(const SUID& other) const
{
    return netId == other.netId && sysId == other.sysId && unitId == other.unitId;
}

/* Checks the WACN ID and System ID ranges. */

bool SUID::validSystem(uint32_t netId, uint32_t sysId)
{
    return netId <= ROAM_MAX_WACN && sysId <= ROAM_MAX_SYSID;
}

/* Packs a WACN ID and System ID into a 32-bit system table key. */

uint32_t SUID::systemKey(uint32_t netId, uint32_t sysId)
{
    return ((netId & ROAM_MAX_WACN) << 12) | (sysId & ROAM_MAX_SYSID);
}

/* Checks the WACN ID and System ID ranges. */

bool RfssIdentity::valid() const
{
    return SUID::validSystem(netId, sysId);
}

/* Compares two RFSS identities. */

bool RfssIdentity::operator==(const RfssIdentity& other) const
{
    return netId == other.netId && sysId == other.sysId && rfssId == other.rfssId;
}
