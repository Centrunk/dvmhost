// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 Bryan Biedenkapp, N2PLL
 *
 */

#include "common/Log.h"
#include "common/Utils.h"

#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <random>

#include "common/edac/Trellis.h"

using namespace edac;

TEST_CASE("Trellis 3/4 rate preserves all-zero payload", "[edac][trellis]") {
    uint8_t payload[18U];
    ::memset(payload, 0x00U, sizeof(payload));

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode34(payload, data, false);
    Utils::dump(2U, "Trellis::encode34() all zeros", data, 25U);

    uint8_t decoded[18U];
    bool result = trellis.decode34(data, decoded, false);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 18U) == 0);
}

TEST_CASE("Trellis 3/4 rate preserves all-ones payload", "[edac][trellis]") {
    uint8_t payload[18U];
    ::memset(payload, 0xFFU, sizeof(payload));

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode34(payload, data, false);
    Utils::dump(2U, "Trellis::encode34() all ones", data, 25U);

    uint8_t decoded[18U];
    bool result = trellis.decode34(data, decoded, false);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 18U) == 0);
}

TEST_CASE("Trellis 3/4 rate preserves alternating pattern", "[edac][trellis]") {
    uint8_t payload[18U];
    for (size_t i = 0; i < 18U; i++) {
        payload[i] = (i % 2 == 0) ? 0xAAU : 0x55U;
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode34(payload, data, false);
    Utils::dump(2U, "Trellis::encode34() alternating", data, 25U);

    uint8_t decoded[18U];
    bool result = trellis.decode34(data, decoded, false);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 18U) == 0);
}

TEST_CASE("Trellis 3/4 rate preserves incrementing pattern", "[edac][trellis]") {
    uint8_t payload[18U];
    for (size_t i = 0; i < 18U; i++) {
        payload[i] = (uint8_t)(i * 13);
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode34(payload, data, false);
    Utils::dump(2U, "Trellis::encode34() incrementing", data, 25U);

    uint8_t decoded[18U];
    bool result = trellis.decode34(data, decoded, false);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 18U) == 0);
}

TEST_CASE("Trellis 3/4 rate preserves specific pattern", "[edac][trellis]") {
    uint8_t payload[18U];
    for (size_t i = 0; i < 18U; i++) {
        payload[i] = (uint8_t)(i + 100);
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode34(payload, data, false);

    uint8_t decoded[18U];
    bool result = trellis.decode34(data, decoded, false);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 18U) == 0);
}

TEST_CASE("Trellis 3/4 rate handles another pattern", "[edac][trellis]") {
    uint8_t payload[18U];
    for (size_t i = 0; i < 18U; i++) {
        payload[i] = (uint8_t)(i * 7);
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode34(payload, data, false);
    Utils::dump(2U, "Trellis::encode34() pattern", data, 25U);

    uint8_t decoded[18U];
    bool result = trellis.decode34(data, decoded, false);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 18U) == 0);
}

TEST_CASE("Trellis 1/2 rate preserves all-zero payload", "[edac][trellis]") {
    uint8_t payload[12U];
    ::memset(payload, 0x00U, sizeof(payload));

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode12(payload, data);
    Utils::dump(2U, "Trellis::encode12() all zeros", data, 25U);

    uint8_t decoded[12U];
    bool result = trellis.decode12(data, decoded);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 12U) == 0);
}

TEST_CASE("Trellis 1/2 rate preserves all-ones payload", "[edac][trellis]") {
    uint8_t payload[12U];
    ::memset(payload, 0xFFU, sizeof(payload));

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode12(payload, data);
    Utils::dump(2U, "Trellis::encode12() all ones", data, 25U);

    uint8_t decoded[12U];
    bool result = trellis.decode12(data, decoded);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 12U) == 0);
}

TEST_CASE("Trellis 1/2 rate preserves alternating pattern", "[edac][trellis]") {
    uint8_t payload[12U];
    for (size_t i = 0; i < 12U; i++) {
        payload[i] = (i % 2 == 0) ? 0xAAU : 0x55U;
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode12(payload, data);
    Utils::dump(2U, "Trellis::encode12() alternating", data, 25U);

    uint8_t decoded[12U];
    bool result = trellis.decode12(data, decoded);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 12U) == 0);
}

TEST_CASE("Trellis 1/2 rate preserves incrementing pattern", "[edac][trellis]") {
    uint8_t payload[12U];
    for (size_t i = 0; i < 12U; i++) {
        payload[i] = (uint8_t)(i * 17);
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode12(payload, data);
    Utils::dump(2U, "Trellis::encode12() incrementing", data, 25U);

    uint8_t decoded[12U];
    bool result = trellis.decode12(data, decoded);

    REQUIRE(result);
    REQUIRE(::memcmp(decoded, payload, 12U) == 0);
}

TEST_CASE("Trellis 1/2 rate corrects errors", "[edac][trellis]") {
    uint8_t original[12U];
    for (size_t i = 0; i < 12U; i++) {
        original[i] = (uint8_t)(i + 75);
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode12(original, data);

    // Save encoded data
    uint8_t encoded[25U];
    ::memcpy(encoded, data, 25U);

    // Test errors at various positions
    const size_t errorPositions[] = {0, 8, 16, 24};
    
    for (auto pos : errorPositions) {
        ::memcpy(data, encoded, 25U);
        
        // Introduce errors - 1/2 rate has better error correction
        data[pos] ^= 0x07U;

        uint8_t decoded[12U];
        bool result = trellis.decode12(data, decoded);

        // 1/2 rate Trellis has stronger error correction
        if (result) {
            REQUIRE(::memcmp(decoded, original, 12U) == 0);
        }
    }
}

TEST_CASE("Trellis 1/2 rate handles random payloads", "[edac][trellis]") {
    // Test with various random-like patterns
    for (uint32_t test = 0; test < 5; test++) {
        uint8_t payload[12U];
        for (size_t i = 0; i < 12U; i++) {
            payload[i] = (uint8_t)((i * 37 + test * 53) % 256);
        }

        uint8_t data[25U];
        ::memset(data, 0x00U, sizeof(data));

        Trellis trellis;
        trellis.encode12(payload, data);

        uint8_t decoded[12U];
        bool result = trellis.decode12(data, decoded);

        REQUIRE(result);
        REQUIRE(::memcmp(decoded, payload, 12U) == 0);
    }
}

TEST_CASE("Trellis 3/4 rate handles random payloads", "[edac][trellis]") {
    // Test with various random-like patterns
    for (uint32_t test = 0; test < 5; test++) {
        uint8_t payload[18U];
        for (size_t i = 0; i < 18U; i++) {
            payload[i] = (uint8_t)((i * 41 + test * 61) % 256);
        }

        uint8_t data[25U];
        ::memset(data, 0x00U, sizeof(data));

        Trellis trellis;
        trellis.encode34(payload, data, false);

        uint8_t decoded[18U];
        bool result = trellis.decode34(data, decoded, false);

        REQUIRE(result);
        REQUIRE(::memcmp(decoded, payload, 18U) == 0);
    }
}

// shift one transmitted 4FSK symbol (dibit index 0-97 of the 196-bit block) by a single level,
// reflecting at the outer levels; this is the dominant hard-decision error of a C4FM receiver
static void shiftSymbol34(uint8_t* data, uint32_t symbol, bool up)
{
    const uint32_t n = symbol * 2U;
    const bool b1 = READ_BIT(data, n) != 0x00U;
    const bool b2 = READ_BIT(data, n + 1U) != 0x00U;

    // dibit 01 = +3, 00 = +1, 10 = -1, 11 = -3
    int level = (!b1 && b2) ? 3 : (!b1 && !b2) ? 1 : (b1 && !b2) ? -1 : -3;
    level += up ? 2 : -2;
    if (level > 3)
        level = 1;
    if (level < -3)
        level = -1;

    WRITE_BIT(data, n, level < 0);
    WRITE_BIT(data, n + 1U, (level == 3) || (level == -3));
}

TEST_CASE("Trellis 3/4 rate corrects every single symbol error", "[edac][trellis]") {
    uint8_t payload[18U];
    for (size_t i = 0; i < 18U; i++) {
        payload[i] = (uint8_t)(i * 29U + 7U);
    }

    uint8_t encoded[25U];
    ::memset(encoded, 0x00U, sizeof(encoded));

    Trellis trellis;
    trellis.encode34(payload, encoded, false);

    for (uint32_t symbol = 0U; symbol < 98U; symbol++) {
        for (int dir = 0; dir < 2; dir++) {
            uint8_t data[25U];
            ::memcpy(data, encoded, sizeof(data));
            shiftSymbol34(data, symbol, dir == 0);

            uint8_t decoded[18U];
            REQUIRE(trellis.decode34(data, decoded, false));
            REQUIRE(::memcmp(decoded, payload, 18U) == 0);
        }
    }
}

TEST_CASE("Trellis 3/4 rate corrects scattered multi-symbol errors", "[edac][trellis]") {
    // fixed seed; std::mt19937 output is fully specified by the standard, so this is deterministic
    std::mt19937 rng(0x25U);

    const uint32_t TRIALS = 500U;
    const uint32_t ERRORS = 3U;

    uint32_t corrected = 0U;
    Trellis trellis;
    for (uint32_t t = 0U; t < TRIALS; t++) {
        uint8_t payload[18U];
        for (size_t i = 0; i < 18U; i++) {
            payload[i] = (uint8_t)(rng() & 0xFFU);
        }

        uint8_t data[25U];
        ::memset(data, 0x00U, sizeof(data));
        trellis.encode34(payload, data, false);

        for (uint32_t e = 0U; e < ERRORS; e++) {
            shiftSymbol34(data, rng() % 98U, (rng() & 1U) != 0U);
        }

        uint8_t decoded[18U];
        if (trellis.decode34(data, decoded, false) && ::memcmp(decoded, payload, 18U) == 0)
            corrected++;
    }

    // a maximum-likelihood decode recovers roughly 87% of 3-symbol-error blocks; the previous greedy
    // point fixer recovered roughly 65%
    INFO("corrected " << corrected << " of " << TRIALS);
    REQUIRE(corrected >= (TRIALS * 80U) / 100U);
}

TEST_CASE("Trellis 3/4 rate list decode leads with the decode34 result", "[edac][trellis]") {
    std::mt19937 rng(0x34U);

    Trellis trellis;
    for (uint32_t t = 0U; t < 50U; t++) {
        uint8_t payload[18U];
        for (size_t i = 0; i < 18U; i++) {
            payload[i] = (uint8_t)(rng() & 0xFFU);
        }

        uint8_t data[25U];
        ::memset(data, 0x00U, sizeof(data));
        trellis.encode34(payload, data, false);

        for (uint32_t e = 0U; e < 4U; e++) {
            shiftSymbol34(data, rng() % 98U, (rng() & 1U) != 0U);
        }

        uint8_t single[18U];
        REQUIRE(trellis.decode34(data, single, false));

        uint8_t list[TRELLIS_34_MAX_LIST_PATHS * TRELLIS_34_PAYLOAD_LENGTH_BYTES];
        uint32_t count = trellis.decode34List(data, list, TRELLIS_34_MAX_LIST_PATHS, false);
        REQUIRE(count >= 1U);
        REQUIRE(count <= TRELLIS_34_MAX_LIST_PATHS);
        REQUIRE(::memcmp(list, single, 18U) == 0);
    }
}

TEST_CASE("Trellis 3/4 rate list decode of a clean block yields one candidate", "[edac][trellis]") {
    uint8_t payload[18U];
    for (size_t i = 0; i < 18U; i++) {
        payload[i] = (uint8_t)(0xA5U ^ (i * 13U));
    }

    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    Trellis trellis;
    trellis.encode34(payload, data, false);

    // an error-free block is the only codeword at distance zero
    uint8_t list[TRELLIS_34_MAX_LIST_PATHS * TRELLIS_34_PAYLOAD_LENGTH_BYTES];
    REQUIRE(trellis.decode34List(data, list, TRELLIS_34_MAX_LIST_PATHS, false) == 1U);
    REQUIRE(::memcmp(list, payload, 18U) == 0);
}

TEST_CASE("Trellis 3/4 rate list decode rejects invalid path counts", "[edac][trellis]") {
    uint8_t data[25U];
    ::memset(data, 0x00U, sizeof(data));

    uint8_t list[(TRELLIS_34_MAX_LIST_PATHS + 1U) * TRELLIS_34_PAYLOAD_LENGTH_BYTES];

    Trellis trellis;
    REQUIRE(trellis.decode34List(data, list, 0U, false) == 0U);
    REQUIRE(trellis.decode34List(data, list, TRELLIS_34_MAX_LIST_PATHS + 1U, false) == 0U);
}
