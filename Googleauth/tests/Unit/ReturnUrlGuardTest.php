<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Security\ReturnUrlGuard;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ReturnUrlGuardTest extends TestCase
{
    #[DataProvider('hostileCandidates')]
    public function testHostileDestinationsAreDiscarded(mixed $candidate): void
    {
        self::assertSame('/', ReturnUrlGuard::sanitize($candidate), var_export($candidate, true));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function hostileCandidates(): iterable
    {
        yield 'absolute http url' => ['http://evil.example/'];
        yield 'absolute https url' => ['https://evil.example/path'];
        yield 'protocol relative' => ['//evil.example/path'];
        yield 'protocol relative with backslash' => ['/\\evil.example'];
        yield 'javascript scheme' => ['javascript:alert(1)'];
        yield 'data scheme' => ['data:text/html,<script>'];
        yield 'scheme after slash' => ['/https://evil.example'];
        yield 'backslash path' => ['\\\\evil.example\\share'];
        yield 'traversal' => ['/client/../../etc/passwd'];
        yield 'dot segment' => ['/./client'];
        yield 'encoded newline' => ["/client%0d%0aSet-Cookie:%20a=b"];
        yield 'raw newline' => ["/client\nSet-Cookie: a=b"];
        yield 'null byte' => ["/client\0"];
        yield 'relative without slash' => ['client/profile'];
        yield 'empty' => [''];
        yield 'whitespace' => ['   '];
        yield 'not a string' => [['/client']];
        yield 'null' => [null];
        yield 'userinfo' => ['//user@evil.example/'];
    }

    public function testOrdinaryInternalPathsSurvive(): void
    {
        self::assertSame('/client/profile', ReturnUrlGuard::sanitize('/client/profile'));
        self::assertSame('/', ReturnUrlGuard::sanitize('/'));
        self::assertSame('/order/service/12', ReturnUrlGuard::sanitize('/order/service/12'));
    }

    public function testQueryStringsAreKeptButFragmentsAreNot(): void
    {
        self::assertSame('/invoice?page=2', ReturnUrlGuard::sanitize('/invoice?page=2'));
        self::assertSame('/invoice', ReturnUrlGuard::sanitize('/invoice#top'));
        self::assertSame('/invoice?page=2', ReturnUrlGuard::sanitize('/invoice?page=2#top'));
    }

    public function testTheFallbackIsConfigurable(): void
    {
        self::assertSame('/login', ReturnUrlGuard::sanitize('https://evil.example', '/login'));
        self::assertSame('/googleauth/account', ReturnUrlGuard::sanitize(null, '/googleauth/account'));
    }

    public function testLinkPathDropsTheLeadingSlashForTheCoreUrlBuilder(): void
    {
        self::assertSame('client/profile', ReturnUrlGuard::toLinkPath('/client/profile'));
        self::assertSame('', ReturnUrlGuard::toLinkPath('/'));
    }
}
