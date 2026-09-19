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
 * Proof Key for Code Exchange (RFC 7636), S256 only.
 *
 * The "plain" method is deliberately not implemented: Google supports S256 and
 * offering a downgrade would only ever weaken the flow.
 */
final class Pkce
{
    public const string METHOD = 'S256';

    /** RFC 7636 allows 43-128 characters; 43 is what 32 random bytes encode to. */
    private const int VERIFIER_BYTES = 32;

    private function __construct(
        public readonly string $verifier,
        public readonly string $challenge,
    ) {
    }

    public static function create(): self
    {
        $verifier = self::base64UrlEncode(random_bytes(self::VERIFIER_BYTES));

        return new self($verifier, self::challengeFor($verifier));
    }

    /**
     * Rebuild the pair from a stored verifier (used when resuming a flow).
     */
    public static function fromVerifier(string $verifier): self
    {
        if (!self::isValidVerifier($verifier)) {
            throw new \InvalidArgumentException('Invalid PKCE code verifier.');
        }

        return new self($verifier, self::challengeFor($verifier));
    }

    public static function challengeFor(string $verifier): string
    {
        return self::base64UrlEncode(hash('sha256', $verifier, true));
    }

    public static function isValidVerifier(string $verifier): bool
    {
        return preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier) === 1;
    }

    public static function base64UrlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * @return string|false decoded bytes, or false when the input is not valid base64url
     */
    public static function base64UrlDecode(string $encoded): string|false
    {
        if (preg_match('/^[A-Za-z0-9\-_]*$/', $encoded) !== 1) {
            return false;
        }

        $padded = strtr($encoded, '-_', '+/');
        $remainder = strlen($padded) % 4;
        if ($remainder !== 0) {
            $padded .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode($padded, true);
    }
}
