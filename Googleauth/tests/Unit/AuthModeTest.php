<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Enum\AuthMode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AuthModeTest extends TestCase
{
    public function testDefaultValueIsLoginOnly(): void
    {
        self::assertSame('login', AuthMode::DEFAULT_VALUE);
        self::assertSame(AuthMode::LoginOnly, AuthMode::from(AuthMode::DEFAULT_VALUE));
    }

    #[DataProvider('unusableValues')]
    public function testUnusableValuesFallBackToLoginOnly(mixed $value): void
    {
        self::assertSame(AuthMode::LoginOnly, AuthMode::fromConfigValue($value));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unusableValues(): iterable
    {
        yield 'null' => [null];
        yield 'empty string' => [''];
        yield 'unknown string' => ['everything'];
        yield 'integer' => [1];
        yield 'array' => [['both']];
        yield 'boolean' => [true];
    }

    public function testKnownValuesAreParsedCaseInsensitively(): void
    {
        self::assertSame(AuthMode::SignupOnly, AuthMode::fromConfigValue(' SIGNUP '));
        self::assertSame(AuthMode::Both, AuthMode::fromConfigValue('both'));
    }

    public function testCapabilities(): void
    {
        self::assertTrue(AuthMode::LoginOnly->allowsLogin());
        self::assertFalse(AuthMode::LoginOnly->allowsSignup());

        self::assertFalse(AuthMode::SignupOnly->allowsLogin());
        self::assertTrue(AuthMode::SignupOnly->allowsSignup());

        self::assertTrue(AuthMode::Both->allowsLogin());
        self::assertTrue(AuthMode::Both->allowsSignup());
    }

    public function testStrictValidationRejectsUnknownValues(): void
    {
        self::assertTrue(AuthMode::isValidValue('login'));
        self::assertTrue(AuthMode::isValidValue('signup'));
        self::assertTrue(AuthMode::isValidValue('both'));
        self::assertFalse(AuthMode::isValidValue('all'));
        self::assertFalse(AuthMode::isValidValue(null));
    }

    public function testOptionsCoverEveryMode(): void
    {
        self::assertSame(
            ['login' => 'Login Only', 'signup' => 'Signup Only', 'both' => 'Login & Signup'],
            AuthMode::options()
        );
    }
}
