// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2016,2018 Jonathan Naylor, G4KLX
 *  Copyright (C) 2023-2024 Bryan Biedenkapp, N2PLL
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "edac/Trellis.h"
#include "Log.h"
#include "Utils.h"

using namespace edac;

#include <cassert>
#include <cstdlib>
#include <cstring>

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

const uint32_t INTERLEAVE_TABLE[] = {
    0U, 1U, 8U,   9U, 16U, 17U, 24U, 25U, 32U, 33U, 40U, 41U, 48U, 49U, 56U, 57U, 64U, 65U, 72U, 73U, 80U, 81U, 88U, 89U, 96U, 97U,
    2U, 3U, 10U, 11U, 18U, 19U, 26U, 27U, 34U, 35U, 42U, 43U, 50U, 51U, 58U, 59U, 66U, 67U, 74U, 75U, 82U, 83U, 90U, 91U,
    4U, 5U, 12U, 13U, 20U, 21U, 28U, 29U, 36U, 37U, 44U, 45U, 52U, 53U, 60U, 61U, 68U, 69U, 76U, 77U, 84U, 85U, 92U, 93U,
    6U, 7U, 14U, 15U, 22U, 23U, 30U, 31U, 38U, 39U, 46U, 47U, 54U, 55U, 62U, 63U, 70U, 71U, 78U, 79U, 86U, 87U, 94U, 95U };

const uint8_t ENCODE_TABLE_34[] = {
    0U,  8U, 4U, 12U, 2U, 10U, 6U, 14U,
    4U, 12U, 2U, 10U, 6U, 14U, 0U,  8U,
    1U,  9U, 5U, 13U, 3U, 11U, 7U, 15U,
    5U, 13U, 3U, 11U, 7U, 15U, 1U,  9U,
    3U, 11U, 7U, 15U, 1U,  9U, 5U, 13U,
    7U, 15U, 1U,  9U, 5U, 13U, 3U, 11U,
    2U, 10U, 6U, 14U, 0U,  8U, 4U, 12U,
    6U, 14U, 0U,  8U, 4U, 12U, 2U, 10U };

const uint8_t ENCODE_TABLE_12[] = {
    0U,  15U, 12U,  3U,
    4U,  11U,  8U,  7U,
    13U,  2U,  1U, 14U,
    9U,   6U,  5U, 10U };

// 4FSK dibit pair carried by each constellation point (same mapping as pointsToDibits())
const int8_t POINT_DIBITS[16U][2U] = {
    { +1, -1 }, { -1, -1 }, { +3, -3 }, { -3, -3 }, { -3, -1 }, { +3, -1 }, { -1, -3 }, { +1, -3 },
    { -3, +3 }, { +3, +3 }, { -1, +1 }, { +1, +1 }, { +1, +3 }, { -1, +3 }, { +3, +1 }, { -3, +1 } };

// number of constellation points (trellis steps) in a 3/4 rate block, including the flushing tribit
const uint32_t TRELLIS_34_STEPS = 49U;
// number of encoder states (the previous tribit) for the 3/4 rate code
const uint32_t TRELLIS_34_STATES = 8U;

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the Trellis class. */

Trellis::Trellis() = default;

/* Finalizes a instance of the Trellis class. */

Trellis::~Trellis() = default;

/* Decodes 3/4 rate Trellis. */

bool Trellis::decode34(const uint8_t* data, uint8_t* payload, bool skipSymbols)
{
    assert(data != nullptr);
    assert(payload != nullptr);

    int8_t dibits[98U];
    deinterleave(data, dibits, skipSymbols);

    uint32_t metric = 0U;
    return viterbi34(dibits, payload, &metric, 1U) == 1U;
}

/* Decodes 3/4 rate Trellis, returning every candidate tied for the best path metric. */

uint32_t Trellis::decode34List(const uint8_t* data, uint8_t* payloads, uint32_t maxPaths, bool skipSymbols)
{
    assert(data != nullptr);
    assert(payloads != nullptr);

    if (maxPaths == 0U || maxPaths > TRELLIS_34_MAX_LIST_PATHS)
        return 0U;

    int8_t dibits[98U];
    deinterleave(data, dibits, skipSymbols);

    uint32_t metrics[TRELLIS_34_MAX_LIST_PATHS];
    uint32_t count = viterbi34(dibits, payloads, metrics, maxPaths);

    // only candidates that are as likely as the best path are useful to the caller; anything worse
    // would let a CRC accept a less likely codeword over a more likely one
    uint32_t tied = 0U;
    while (tied < count && metrics[tied] == metrics[0U])
        tied++;

    return tied;
}

/* Encodes 3/4 rate Trellis. */

void Trellis::encode34(const uint8_t* payload, uint8_t* data, bool skipSymbols)
{
    assert(payload != nullptr);
    assert(data != nullptr);

    uint8_t tribits[49U];
    bitsToTribits(payload, tribits);

    uint8_t points[49U];
    uint8_t state = 0U;

    for (uint32_t i = 0U; i < 49U; i++) {
        uint8_t tribit = tribits[i];

        points[i] = ENCODE_TABLE_34[state * 8U + tribit];

        state = tribit;
    }

    int8_t dibits[98U];
    pointsToDibits(points, dibits);

    interleave(dibits, data, skipSymbols);
}

/* Decodes 1/2 rate Trellis. */

bool Trellis::decode12(const uint8_t* data, uint8_t* payload)
{
    assert(data != nullptr);
    assert(payload != nullptr);

    int8_t dibits[98U];
    deinterleave(data, dibits);

    uint8_t points[49U];
    dibitsToPoints(dibits, points);

    // Check the original code
    uint8_t bits[49U];
    uint32_t failPos = checkCode12(points, bits);
    if (failPos == 999U) {
        dibitsToBits(bits, payload);
        return true;
    }

    uint8_t savePoints[49U];
    for (uint32_t i = 0U; i < 49U; i++)
        savePoints[i] = points[i];

    bool ret = fixCode12(points, failPos, payload);
    if (ret)
        return true;

    if (failPos == 0U)
        return false;

    // Backtrack one place for a last go
    return fixCode12(savePoints, failPos - 1U, payload);
}

/* Encodes 1/2 rate Trellis. */

void Trellis::encode12(const uint8_t* payload, uint8_t* data)
{
    assert(payload != nullptr);
    assert(data != nullptr);

    uint8_t bits[49U];
    bitsToDibits(payload, bits);

    uint8_t points[49U];
    uint8_t state = 0U;

    for (uint32_t i = 0U; i < 49U; i++) {
        uint8_t bit = bits[i];

        points[i] = ENCODE_TABLE_12[state * 4U + bit];

        state = bit;
    }

    int8_t dibits[98U];
    pointsToDibits(points, dibits);

    interleave(dibits, data);
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Helper to deinterleave the input symbols into dibits. */

void Trellis::deinterleave(const uint8_t* data, int8_t* dibits, bool skipSymbols) const
{
    for (uint32_t i = 0U; i < 98U; i++) {
        uint32_t n = i * 2U + 0U;
        if (skipSymbols && n >= 98U) n += 68U;
        bool b1 = READ_BIT(data, n) != 0x00U;

        n = i * 2U + 1U;
        if (skipSymbols && n >= 98U) n += 68U;
        bool b2 = READ_BIT(data, n) != 0x00U;

        int8_t dibit;
        if (!b1 && b2)
            dibit = +3;
        else if (!b1 && !b2)
            dibit = +1;
        else if (b1 && !b2)
            dibit = -1;
        else
            dibit = -3;

        n = INTERLEAVE_TABLE[i];
        dibits[n] = dibit;
    }
}

/* Helper to interleave the input dibits into symbols. */

void Trellis::interleave(const int8_t* dibits, uint8_t* data, bool skipSymbols) const
{
    for (uint32_t i = 0U; i < 98U; i++) {
        uint32_t n = INTERLEAVE_TABLE[i];

        bool b1, b2;
        switch (dibits[n]) {
            case +3:
                b1 = false;
                b2 = true;
                break;
            case +1:
                b1 = false;
                b2 = false;
                break;
            case -1:
                b1 = true;
                b2 = false;
                break;
            default:
                b1 = true;
                b2 = true;
                break;
        }

        n = i * 2U + 0U;
        if (skipSymbols && n >= 98U) n += 68U;
        WRITE_BIT(data, n, b1);

        n = i * 2U + 1U;
        if (skipSymbols && n >= 98U) n += 68U;
        WRITE_BIT(data, n, b2);
    }
}

/* Helper to map dibits to 4FSK constellation points. */

void Trellis::dibitsToPoints(const int8_t* dibits, uint8_t* points) const
{
    for (uint32_t i = 0U; i < 49U; i++) {
        if (dibits[i * 2U + 0U] == +1 && dibits[i * 2U + 1U] == -1)
            points[i] = 0U;
        else if (dibits[i * 2U + 0U] == -1 && dibits[i * 2U + 1U] == -1)
            points[i] = 1U;
        else if (dibits[i * 2U + 0U] == +3 && dibits[i * 2U + 1U] == -3)
            points[i] = 2U;
        else if (dibits[i * 2U + 0U] == -3 && dibits[i * 2U + 1U] == -3)
            points[i] = 3U;
        else if (dibits[i * 2U + 0U] == -3 && dibits[i * 2U + 1U] == -1)
            points[i] = 4U;
        else if (dibits[i * 2U + 0U] == +3 && dibits[i * 2U + 1U] == -1)
            points[i] = 5U;
        else if (dibits[i * 2U + 0U] == -1 && dibits[i * 2U + 1U] == -3)
            points[i] = 6U;
        else if (dibits[i * 2U + 0U] == +1 && dibits[i * 2U + 1U] == -3)
            points[i] = 7U;
        else if (dibits[i * 2U + 0U] == -3 && dibits[i * 2U + 1U] == +3)
            points[i] = 8U;
        else if (dibits[i * 2U + 0U] == +3 && dibits[i * 2U + 1U] == +3)
            points[i] = 9U;
        else if (dibits[i * 2U + 0U] == -1 && dibits[i * 2U + 1U] == +1)
            points[i] = 10U;
        else if (dibits[i * 2U + 0U] == +1 && dibits[i * 2U + 1U] == +1)
            points[i] = 11U;
        else if (dibits[i * 2U + 0U] == +1 && dibits[i * 2U + 1U] == +3)
            points[i] = 12U;
        else if (dibits[i * 2U + 0U] == -1 && dibits[i * 2U + 1U] == +3)
            points[i] = 13U;
        else if (dibits[i * 2U + 0U] == +3 && dibits[i * 2U + 1U] == +1)
            points[i] = 14U;
        else if (dibits[i * 2U + 0U] == -3 && dibits[i * 2U + 1U] == +1)
            points[i] = 15U;
    }
}

/* Helper to map 4FSK constellation points to dibits. */

void Trellis::pointsToDibits(const uint8_t* points, int8_t* dibits) const
{
    for (uint32_t i = 0U; i < 49U; i++) {
        switch (points[i]) {
            case 0U:
                dibits[i * 2U + 0U] = +1;
                dibits[i * 2U + 1U] = -1;
                break;
            case 1U:
                dibits[i * 2U + 0U] = -1;
                dibits[i * 2U + 1U] = -1;
                break;
            case 2U:
                dibits[i * 2U + 0U] = +3;
                dibits[i * 2U + 1U] = -3;
                break;
            case 3U:
                dibits[i * 2U + 0U] = -3;
                dibits[i * 2U + 1U] = -3;
                break;
            case 4U:
                dibits[i * 2U + 0U] = -3;
                dibits[i * 2U + 1U] = -1;
                break;
            case 5U:
                dibits[i * 2U + 0U] = +3;
                dibits[i * 2U + 1U] = -1;
                break;
            case 6U:
                dibits[i * 2U + 0U] = -1;
                dibits[i * 2U + 1U] = -3;
                break;
            case 7U:
                dibits[i * 2U + 0U] = +1;
                dibits[i * 2U + 1U] = -3;
                break;
            case 8U:
                dibits[i * 2U + 0U] = -3;
                dibits[i * 2U + 1U] = +3;
                break;
            case 9U:
                dibits[i * 2U + 0U] = +3;
                dibits[i * 2U + 1U] = +3;
                break;
            case 10U:
                dibits[i * 2U + 0U] = -1;
                dibits[i * 2U + 1U] = +1;
                break;
            case 11U:
                dibits[i * 2U + 0U] = +1;
                dibits[i * 2U + 1U] = +1;
                break;
            case 12U:
                dibits[i * 2U + 0U] = +1;
                dibits[i * 2U + 1U] = +3;
                break;
            case 13U:
                dibits[i * 2U + 0U] = -1;
                dibits[i * 2U + 1U] = +3;
                break;
            case 14U:
                dibits[i * 2U + 0U] = +3;
                dibits[i * 2U + 1U] = +1;
                break;
            default:
                dibits[i * 2U + 0U] = -3;
                dibits[i * 2U + 1U] = +1;
                break;
        }
    }
}

/* Helper to convert a byte payload into tribits. */

void Trellis::bitsToTribits(const uint8_t* payload, uint8_t* tribits) const
{
    for (uint32_t i = 0U; i < 48U; i++) {
        uint32_t n = i * 3U;

        bool b1 = READ_BIT(payload, n) != 0x00U;
        n++;
        bool b2 = READ_BIT(payload, n) != 0x00U;
        n++;
        bool b3 = READ_BIT(payload, n) != 0x00U;

        uint8_t tribit = 0U;
        tribit |= b1 ? 4U : 0U;
        tribit |= b2 ? 2U : 0U;
        tribit |= b3 ? 1U : 0U;

        tribits[i] = tribit;
    }

    tribits[48U] = 0U;
}

/* Helper to convert a byte payload into dibits. */

void Trellis::bitsToDibits(const uint8_t* payload, uint8_t* dibits) const
{
    for (uint32_t i = 0U; i < 48U; i++) {
        uint32_t n = i * 2U;

        bool b1 = READ_BIT(payload, n) != 0x00U;
        n++;
        bool b2 = READ_BIT(payload, n) != 0x00U;

        uint8_t dibit = 0U;
        dibit |= b1 ? 2U : 0U;
        dibit |= b2 ? 1U : 0U;

        dibits[i] = dibit;
    }

    dibits[48U] = 0U;
}

/* Helper to convert tribits into a byte payload. */

void Trellis::tribitsToBits(const uint8_t* tribits, uint8_t* payload) const
{
    for (uint32_t i = 0U; i < 48U; i++) {
        uint8_t tribit = tribits[i];

        bool b1 = (tribit & 0x04U) == 0x04U;
        bool b2 = (tribit & 0x02U) == 0x02U;
        bool b3 = (tribit & 0x01U) == 0x01U;

        uint32_t n = i * 3U;

        WRITE_BIT(payload, n, b1);
        n++;
        WRITE_BIT(payload, n, b2);
        n++;
        WRITE_BIT(payload, n, b3);
    }
}

/* Helper to convert tribits into a byte payload. */

void Trellis::dibitsToBits(const uint8_t* dibits, uint8_t* payload) const
{
    for (uint32_t i = 0U; i < 48U; i++) {
        uint8_t dibit = dibits[i];

        bool b1 = (dibit & 0x02U) == 0x02U;
        bool b2 = (dibit & 0x01U) == 0x01U;

        uint32_t n = i * 2U;

        WRITE_BIT(payload, n, b1);
        n++;
        WRITE_BIT(payload, n, b2);
    }
}

/* Helper to run a list Viterbi decode of the 3/4 rate Trellis. */

uint32_t Trellis::viterbi34(const int8_t* dibits, uint8_t* payloads, uint32_t* metrics, uint32_t maxPaths) const
{
    assert(dibits != nullptr);
    assert(payloads != nullptr);
    assert(metrics != nullptr);
    assert(maxPaths >= 1U && maxPaths <= TRELLIS_34_MAX_LIST_PATHS);

    /*
    ** Parallel list Viterbi: every state keeps its maxPaths best survivors. The encoder state is the
    ** previous tribit, so the input tribit selected at step i is also the state entered at step i. The
    ** branch metric is the 4FSK level distance between the expected and received dibits (one unit per
    ** adjacent level), which matches the dominant hard-decision error of a C4FM receiver: a symbol
    ** sliced one level away from where it was sent.
    */
    struct Survivor {
        uint16_t metric;    // accumulated path metric
        uint8_t prevState;  // state at the previous step
        uint8_t prevRank;   // rank of the predecessor survivor within prevState
    };

    Survivor trace[TRELLIS_34_STEPS][TRELLIS_34_STATES][TRELLIS_34_MAX_LIST_PATHS];
    uint8_t traceCnt[TRELLIS_34_STEPS][TRELLIS_34_STATES];
    ::memset(traceCnt, 0x00U, sizeof(traceCnt));

    // the encoder starts in state 0 with a zero metric
    Survivor current[TRELLIS_34_STATES][TRELLIS_34_MAX_LIST_PATHS];
    uint8_t currentCnt[TRELLIS_34_STATES];
    ::memset(currentCnt, 0x00U, sizeof(currentCnt));
    current[0U][0U] = { 0U, 0U, 0U };
    currentCnt[0U] = 1U;

    for (uint32_t i = 0U; i < TRELLIS_34_STEPS; i++) {
        const int8_t rx0 = dibits[i * 2U + 0U];
        const int8_t rx1 = dibits[i * 2U + 1U];

        for (uint32_t next = 0U; next < TRELLIS_34_STATES; next++) {
            Survivor* best = trace[i][next];
            uint32_t bestCnt = 0U;

            // states and ranks are visited in ascending order and ties never displace an earlier entry,
            // so the candidate ordering is deterministic
            for (uint32_t state = 0U; state < TRELLIS_34_STATES; state++) {
                const uint8_t point = ENCODE_TABLE_34[state * 8U + next];
                const uint32_t branch = (uint32_t)((::abs(POINT_DIBITS[point][0U] - rx0) + ::abs(POINT_DIBITS[point][1U] - rx1)) / 2);

                for (uint32_t rank = 0U; rank < currentCnt[state]; rank++) {
                    const uint16_t metric = (uint16_t)(current[state][rank].metric + branch);
                    if (bestCnt == maxPaths && metric >= best[bestCnt - 1U].metric)
                        continue;

                    // insertion into the sorted survivor list
                    uint32_t pos = (bestCnt < maxPaths) ? bestCnt++ : bestCnt - 1U;
                    while (pos > 0U && best[pos - 1U].metric > metric) {
                        best[pos] = best[pos - 1U];
                        pos--;
                    }

                    best[pos] = { metric, (uint8_t)state, (uint8_t)rank };
                }
            }

            traceCnt[i][next] = (uint8_t)bestCnt;
        }

        for (uint32_t state = 0U; state < TRELLIS_34_STATES; state++) {
            currentCnt[state] = traceCnt[i][state];
            for (uint32_t rank = 0U; rank < currentCnt[state]; rank++)
                current[state][rank] = trace[i][state][rank];
        }
    }

    // the final (flushing) tribit is always 0, so only paths ending in state 0 are valid
    const uint32_t count = traceCnt[TRELLIS_34_STEPS - 1U][0U];
    for (uint32_t path = 0U; path < count; path++) {
        uint8_t tribits[TRELLIS_34_STEPS];
        uint8_t state = 0U;
        uint8_t rank = (uint8_t)path;

        metrics[path] = trace[TRELLIS_34_STEPS - 1U][0U][path].metric;
        for (int32_t i = (int32_t)TRELLIS_34_STEPS - 1; i >= 0; i--) {
            const Survivor& s = trace[i][state][rank];
            tribits[i] = state;
            state = s.prevState;
            rank = s.prevRank;
        }

        tribitsToBits(tribits, payloads + path * TRELLIS_34_PAYLOAD_LENGTH_BYTES);
    }

    return count;
}


/* Helper to fix errors in Trellis coding. */

bool Trellis::fixCode12(uint8_t* points, uint32_t failPos, uint8_t* payload) const
{
#if DEBUG_TRELLIS
    ::LogDebugEx(LOG_HOST, "Trellis::fixCode12()", "failPos = %u, val = %01X", failPos, points[failPos]);
#endif
    for (unsigned j = 0U; j < 20U; j++) {
        uint32_t bestPos = 0U;
        uint32_t bestVal = 0U;

        for (uint32_t i = 0U; i < 16U; i++) {
            points[failPos] = i;

            uint8_t dibits[49U];
            uint32_t pos = checkCode12(points, dibits);
            if (pos == 999U) {
#if DEBUG_TRELLIS
                ::LogDebugEx(LOG_HOST, "Trellis::fixCode12()", "fixed, failPos = %u, pos = %u, val = %01X", failPos, bestPos, bestVal);
#endif
                dibitsToBits(dibits, payload);
                return true;
            }

            if (pos > bestPos) {
                bestPos = pos;
                bestVal = i;
            }
        }

        points[failPos] = bestVal;
        failPos = bestPos;
    }

    return false;
}

/* Helper to detect errors in Trellis coding. */

uint32_t Trellis::checkCode12(const uint8_t* points, uint8_t* dibits) const
{
    uint8_t state = 0U;

    for (uint32_t i = 0U; i < 49U; i++) {
        dibits[i] = 5U;

        for (uint32_t j = 0U; j < 4U; j++) {
            if (points[i] == ENCODE_TABLE_12[state * 4U + j]) {
                dibits[i] = j;
                break;
            }
        }

        if (dibits[i] == 5U)
            return i;

        state = dibits[i];
    }

    if (dibits[48U] != 0U)
        return 48U;

    return 999U;
}
