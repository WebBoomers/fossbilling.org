<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Config\ConfigValidator;
use Box\Mod\Googleauth\Exception\ConfigurationException;
use PHPUnit\Framework\TestCase;

final class ConfigValidatorTest extends TestCase
{
    private ConfigValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new ConfigValidator();
    }

    public function testAnEmptySubmissionProducesTheSafeDefaults(): void
    {
        $result = $this->validator->validate([]);

        self::assertFalse($result['enabled']);
        self::assertSame('login', $result['auth_mode']);
        self::assertSame('', $result['client_id']);
        self::assertSame('', $result['client_secret']);
    }

    public function testInvalidModeIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->validator->validate(['auth_mode' => 'login-and-delete-everything']);
    }

    public function testEnablingWithoutCredentialsIsRefused(): void
    {
        try {
            $this->validator->validate(['enabled' => '1', 'auth_mode' => 'both']);
            self::fail('Enabling without credentials must be refused.');
        } catch (ConfigurationException $e) {
            self::assertStringContainsString('client ID and client secret', $e->getUserMessage());
        }
    }

    public function testEnablingWithOnlyAClientIdIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->validator->validate([
            'enabled' => '1',
            'client_id' => '1234-abc.apps.googleusercontent.com',
        ]);
    }

    public function testABlankSecretKeepsTheStoredOne(): void
    {
        $result = $this->validator->validate([
            'enabled' => '1',
            'auth_mode' => 'both',
            'client_id' => '1234-abc.apps.googleusercontent.com',
            'client_secret' => '',
        ], 'stored-secret');

        self::assertSame('stored-secret', $result['client_secret']);
        self::assertTrue($result['enabled']);
        self::assertSame('both', $result['auth_mode']);
    }

    public function testASubmittedSecretReplacesTheStoredOne(): void
    {
        $result = $this->validator->validate([
            'enabled' => '1',
            'client_id' => '1234-abc.apps.googleusercontent.com',
            'client_secret' => '  new-secret  ',
        ], 'stored-secret');

        self::assertSame('new-secret', $result['client_secret']);
    }

    public function testClearingTheClientIdAlsoClearsTheSecretAndTurnsItOff(): void
    {
        $result = $this->validator->validate([
            'enabled' => '0',
            'client_id' => '',
        ], 'stored-secret');

        self::assertSame('', $result['client_id']);
        self::assertSame('', $result['client_secret']);
        self::assertFalse($result['enabled']);
    }

    public function testAMalformedClientIdIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->validator->validate(['client_id' => 'not a client id']);
    }

    public function testControlCharactersArePulledOutOfPastedCredentials(): void
    {
        $result = $this->validator->validate([
            'enabled' => '1',
            'client_id' => "1234-abc.apps.googleusercontent.com\n",
            'client_secret' => "GOCSPX-example\r\n",
        ]);

        self::assertSame('1234-abc.apps.googleusercontent.com', $result['client_id']);
        self::assertSame('GOCSPX-example', $result['client_secret']);
    }

    public function testAnAbsurdlyLongSecretIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->validator->validate([
            'client_id' => '1234-abc.apps.googleusercontent.com',
            'client_secret' => str_repeat('x', 513),
        ]);
    }

    public function testLinkByVerifiedEmailDefaultsToOffWhenAbsent(): void
    {
        $result = $this->validator->validate(['client_id' => '1234-abc.apps.googleusercontent.com']);

        self::assertFalse($result['link_by_verified_email']);
    }

    public function testLinkByVerifiedEmailIsAcceptedWhenExplicitlySet(): void
    {
        $result = $this->validator->validate([
            'enabled' => '1',
            'client_id' => '1234-abc.apps.googleusercontent.com',
            'client_secret' => 'GOCSPX-example',
            'link_by_verified_email' => '1',
        ]);

        self::assertTrue($result['link_by_verified_email']);
    }

    public function testAnUncheckedBoxTurnsLinkByVerifiedEmailOff(): void
    {
        // An unchecked checkbox is simply absent from the submission, which must
        // switch the setting off rather than leave it on.
        $result = $this->validator->validate([
            'enabled' => '1',
            'client_id' => '1234-abc.apps.googleusercontent.com',
            'client_secret' => 'GOCSPX-example',
        ]);

        self::assertFalse($result['link_by_verified_email']);
    }
}
