<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\OAuth\StateToken;
use PHPUnit\Framework\TestCase;

final class StateTokenTest extends TestCase
{
    public function testTokensAre256BitsOfHex(): void
    {
        $token = StateToken::generate();

        self::assertSame(64, strlen($token));
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $token);
    }

    public function testTokensDoNotRepeat(): void
    {
        $tokens = [];
        for ($i = 0; $i < 100; ++$i) {
            $tokens[StateToken::generate()] = true;
        }

        self::assertCount(100, $tokens);
    }

    public function testMatchingRequiresAnExactPair(): void
    {
        $token = StateToken::generate();

        self::assertTrue(StateToken::matches($token, $token));
        self::assertFalse(StateToken::matches($token, StateToken::generate()));
        self::assertFalse(StateToken::matches($token, strtoupper($token)));
        self::assertFalse(StateToken::matches($token, substr($token, 0, 63)));
    }

    public function testAbsentOrNonStringValuesNeverMatch(): void
    {
        $token = StateToken::generate();

        self::assertFalse(StateToken::matches($token, null));
        self::assertFalse(StateToken::matches($token, ''));
        self::assertFalse(StateToken::matches($token, ['x']));
        self::assertFalse(StateToken::matches($token, 12345));
        self::assertFalse(StateToken::matches(null, $token));
        self::assertFalse(StateToken::matches('', ''));
    }

    public function testWellFormednessCheck(): void
    {
        self::assertTrue(StateToken::isWellFormed(StateToken::generate()));
        self::assertFalse(StateToken::isWellFormed('nothex' . str_repeat('0', 58)));
        self::assertFalse(StateToken::isWellFormed(''));
    }
}
