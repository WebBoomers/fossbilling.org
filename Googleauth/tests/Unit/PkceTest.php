<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\OAuth\Pkce;
use PHPUnit\Framework\TestCase;

final class PkceTest extends TestCase
{
    public function testOnlyS256IsOffered(): void
    {
        self::assertSame('S256', Pkce::METHOD);
    }

    public function testTheRfc7636ReferenceVector(): void
    {
        // RFC 7636, Appendix B.
        self::assertSame(
            'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            Pkce::challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
        );
    }

    public function testGeneratedVerifiersAreValidAndUnpredictable(): void
    {
        $seen = [];

        for ($i = 0; $i < 50; ++$i) {
            $pkce = Pkce::create();

            self::assertTrue(Pkce::isValidVerifier($pkce->verifier));
            self::assertSame(Pkce::challengeFor($pkce->verifier), $pkce->challenge);
            self::assertNotSame($pkce->verifier, $pkce->challenge);

            $seen[$pkce->verifier] = true;
        }

        self::assertCount(50, $seen, 'Every generated verifier must be unique.');
    }

    public function testChallengeIsUrlSafeAndUnpadded(): void
    {
        $challenge = Pkce::create()->challenge;

        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]{43}$/', $challenge);
    }

    public function testVerifierValidationBoundaries(): void
    {
        self::assertFalse(Pkce::isValidVerifier(''));
        self::assertFalse(Pkce::isValidVerifier(str_repeat('a', 42)));
        self::assertTrue(Pkce::isValidVerifier(str_repeat('a', 43)));
        self::assertTrue(Pkce::isValidVerifier(str_repeat('a', 128)));
        self::assertFalse(Pkce::isValidVerifier(str_repeat('a', 129)));
        self::assertFalse(Pkce::isValidVerifier(str_repeat('a', 50) . '/'));
    }

    public function testRebuildingFromAVerifierRejectsRubbish(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Pkce::fromVerifier('too-short');
    }

    public function testBase64UrlRoundTrip(): void
    {
        $raw = random_bytes(64);
        $encoded = Pkce::base64UrlEncode($raw);

        self::assertStringNotContainsString('=', $encoded);
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
        self::assertSame($raw, Pkce::base64UrlDecode($encoded));
    }

    public function testBase64UrlDecodeRejectsNonBase64Url(): void
    {
        self::assertFalse(Pkce::base64UrlDecode('not valid!'));
        self::assertFalse(Pkce::base64UrlDecode('abc+def/ghi'));
    }
}
