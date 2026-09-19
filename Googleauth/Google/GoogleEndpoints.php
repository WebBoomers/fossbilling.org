<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Google;

/**
 * Google's OpenID Connect endpoints.
 *
 * Read from Google's discovery document when it is reachable, so a future change
 * on Google's side is picked up automatically, and falling back to the currently
 * documented URLs when it is not - a discovery outage must not take client
 * logins down on its own.
 */
final class GoogleEndpoints
{
    public const string DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration';

    public const string DEFAULT_AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
    public const string DEFAULT_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
    public const string DEFAULT_JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs';

    public function __construct(
        public readonly string $authorizationEndpoint = self::DEFAULT_AUTHORIZATION_ENDPOINT,
        public readonly string $tokenEndpoint = self::DEFAULT_TOKEN_ENDPOINT,
        public readonly string $jwksUri = self::DEFAULT_JWKS_URI,
    ) {
    }

    /**
     * Build from a discovery document, ignoring any entry that is not an https
     * URL on a Google host so a poisoned response cannot redirect the flow.
     *
     * @param array<string, mixed> $document
     */
    public static function fromDiscoveryDocument(array $document): self
    {
        return new self(
            self::pick($document, 'authorization_endpoint', self::DEFAULT_AUTHORIZATION_ENDPOINT),
            self::pick($document, 'token_endpoint', self::DEFAULT_TOKEN_ENDPOINT),
            self::pick($document, 'jwks_uri', self::DEFAULT_JWKS_URI),
        );
    }

    /**
     * @param array<string, mixed> $document
     */
    private static function pick(array $document, string $key, string $fallback): string
    {
        $value = $document[$key] ?? null;
        if (!is_string($value) || !self::isTrustedGoogleUrl($value)) {
            return $fallback;
        }

        return $value;
    }

    public static function isTrustedGoogleUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https') {
            return false;
        }

        $host = strtolower((string) ($parts['host'] ?? ''));

        foreach (['google.com', 'googleapis.com', 'googleusercontent.com'] as $suffix) {
            if ($host === $suffix || str_ends_with($host, '.' . $suffix)) {
                return true;
            }
        }

        return false;
    }
}
