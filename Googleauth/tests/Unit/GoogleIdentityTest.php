<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Google\GoogleIdentity;
use PHPUnit\Framework\TestCase;

final class GoogleIdentityTest extends TestCase
{
    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function claims(array $overrides = []): array
    {
        return array_merge([
            'sub' => '110248495921238986420',
            'email' => 'Customer@Example.com',
            'email_verified' => true,
            'name' => 'Ada Lovelace',
            'given_name' => 'Ada',
            'family_name' => 'Lovelace',
            'picture' => 'https://lh3.googleusercontent.com/a/example',
        ], $overrides);
    }

    public function testClaimsAreMappedAndTheEmailIsNormalised(): void
    {
        $identity = GoogleIdentity::fromClaims($this->claims());

        self::assertSame('110248495921238986420', $identity->subject);
        self::assertSame('customer@example.com', $identity->email);
        self::assertTrue($identity->emailVerified);
        self::assertSame('Ada', $identity->givenName);
        self::assertSame('Lovelace', $identity->familyName);
    }

    public function testAnIdentityWithoutASubjectIsRefused(): void
    {
        $this->expectException(GoogleAuthException::class);
        GoogleIdentity::fromClaims($this->claims(['sub' => '']));
    }

    public function testAnIdentityWithoutAnEmailIsRefused(): void
    {
        try {
            GoogleIdentity::fromClaims($this->claims(['email' => null]));
            self::fail('An identity with no email address must be refused.');
        } catch (GoogleAuthException $e) {
            self::assertStringContainsString('email address', $e->getUserMessage());
        }
    }

    public function testUnverifiedEmailsAreRejectedAtTheGate(): void
    {
        $identity = GoogleIdentity::fromClaims($this->claims(['email_verified' => false]));

        self::assertFalse($identity->emailVerified);

        $this->expectException(GoogleAuthException::class);
        $identity->assertEmailVerified();
    }

    public function testGoogleStringBooleansAreUnderstood(): void
    {
        self::assertTrue(GoogleIdentity::fromClaims($this->claims(['email_verified' => 'true']))->emailVerified);
        self::assertTrue(GoogleIdentity::fromClaims($this->claims(['email_verified' => 1]))->emailVerified);
        self::assertFalse(GoogleIdentity::fromClaims($this->claims(['email_verified' => 'false']))->emailVerified);
        self::assertFalse(GoogleIdentity::fromClaims($this->claims(['email_verified' => null]))->emailVerified);
    }

    public function testNameFallbacks(): void
    {
        $withoutGivenName = GoogleIdentity::fromClaims($this->claims(['given_name' => null]));
        self::assertSame('Ada Lovelace', $withoutGivenName->firstName());

        $withoutAnyName = GoogleIdentity::fromClaims($this->claims([
            'given_name' => null,
            'name' => null,
            'family_name' => null,
        ]));
        self::assertSame('customer', $withoutAnyName->firstName());
        self::assertNull($withoutAnyName->lastName());
    }

    public function testTheSubjectIsWhatIdentifiesSomeone(): void
    {
        $first = GoogleIdentity::fromClaims($this->claims(['sub' => 'aaa']));
        $second = GoogleIdentity::fromClaims($this->claims(['sub' => 'bbb']));

        // Same email address, different people: the extension must be able to
        // tell them apart, which is why `sub` is the identifier.
        self::assertSame($first->email, $second->email);
        self::assertNotSame($first->subject, $second->subject);
    }
}
