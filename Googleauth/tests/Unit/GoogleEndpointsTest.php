<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Google\GoogleEndpoints;
use PHPUnit\Framework\TestCase;

final class GoogleEndpointsTest extends TestCase
{
    public function testDefaultsAreGooglesDocumentedEndpoints(): void
    {
        $endpoints = new GoogleEndpoints();

        self::assertSame('https://accounts.google.com/o/oauth2/v2/auth', $endpoints->authorizationEndpoint);
        self::assertSame('https://oauth2.googleapis.com/token', $endpoints->tokenEndpoint);
        self::assertSame('https://www.googleapis.com/oauth2/v3/certs', $endpoints->jwksUri);
    }

    public function testADiscoveryDocumentIsHonoured(): void
    {
        $endpoints = GoogleEndpoints::fromDiscoveryDocument([
            'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v3/auth',
            'token_endpoint' => 'https://oauth2.googleapis.com/token/v2',
            'jwks_uri' => 'https://www.googleapis.com/oauth2/v4/certs',
        ]);

        self::assertSame('https://accounts.google.com/o/oauth2/v3/auth', $endpoints->authorizationEndpoint);
        self::assertSame('https://oauth2.googleapis.com/token/v2', $endpoints->tokenEndpoint);
        self::assertSame('https://www.googleapis.com/oauth2/v4/certs', $endpoints->jwksUri);
    }

    public function testAPoisonedDiscoveryDocumentCannotRedirectTheFlow(): void
    {
        $endpoints = GoogleEndpoints::fromDiscoveryDocument([
            'authorization_endpoint' => 'https://accounts.evil.example/auth',
            'token_endpoint' => 'http://oauth2.googleapis.com/token',
            'jwks_uri' => 'https://googleapis.com.evil.example/certs',
        ]);

        self::assertSame(GoogleEndpoints::DEFAULT_AUTHORIZATION_ENDPOINT, $endpoints->authorizationEndpoint, 'A non-Google host must be ignored.');
        self::assertSame(GoogleEndpoints::DEFAULT_TOKEN_ENDPOINT, $endpoints->tokenEndpoint, 'A plaintext endpoint must be ignored.');
        self::assertSame(GoogleEndpoints::DEFAULT_JWKS_URI, $endpoints->jwksUri, 'A look-alike host must be ignored.');
    }

    public function testAnEmptyDocumentFallsBackCompletely(): void
    {
        $endpoints = GoogleEndpoints::fromDiscoveryDocument([]);

        self::assertSame(GoogleEndpoints::DEFAULT_AUTHORIZATION_ENDPOINT, $endpoints->authorizationEndpoint);
        self::assertSame(GoogleEndpoints::DEFAULT_TOKEN_ENDPOINT, $endpoints->tokenEndpoint);
        self::assertSame(GoogleEndpoints::DEFAULT_JWKS_URI, $endpoints->jwksUri);
    }

    public function testHostTrustCheck(): void
    {
        self::assertTrue(GoogleEndpoints::isTrustedGoogleUrl('https://accounts.google.com/x'));
        self::assertTrue(GoogleEndpoints::isTrustedGoogleUrl('https://oauth2.googleapis.com/token'));
        self::assertFalse(GoogleEndpoints::isTrustedGoogleUrl('https://notgoogle.com/x'));
        self::assertFalse(GoogleEndpoints::isTrustedGoogleUrl('https://google.com.evil.example/x'));
        self::assertFalse(GoogleEndpoints::isTrustedGoogleUrl('ftp://accounts.google.com/x'));
        self::assertFalse(GoogleEndpoints::isTrustedGoogleUrl('nonsense'));
    }
}
