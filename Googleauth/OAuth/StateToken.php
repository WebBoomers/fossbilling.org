<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\OAuth;

/**
 * Cryptographically secure, single-use OAuth `state` and OpenID Connect `nonce`
 * values.
 *
 * Both are produced the same way (32 random bytes, hex encoded) and are always
 * compared with hash_equals() so that a comparison never leaks timing
 * information about the expected value.
 */
final class StateToken
{
    private const int TOKEN_BYTES = 32;

    public static function generate(): string
    {
        return bin2hex(random_bytes(self::TOKEN_BYTES));
    }

    /**
     * A missing, empty or malformed value is rejected before the comparison, so
     * a callback without a state can never be treated as a match.
     */
    public static function matches(?string $expected, mixed $provided): bool
    {
        if (!is_string($expected) || !is_string($provided)) {
            return false;
        }

        if ($expected === '' || $provided === '') {
            return false;
        }

        if (!self::isWellFormed($expected) || !self::isWellFormed($provided)) {
            return false;
        }

        return hash_equals($expected, $provided);
    }

    public static function isWellFormed(string $token): bool
    {
        return preg_match('/^[a-f0-9]{' . (self::TOKEN_BYTES * 2) . '}$/', $token) === 1;
    }
}
