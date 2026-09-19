<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Config\ExtensionConfig;
use Box\Mod\Googleauth\Enum\AuthMode;
use Box\Mod\Googleauth\Exception\ConfigurationException;
use PHPUnit\Framework\TestCase;

final class ExtensionConfigTest extends TestCase
{
    public function testAFreshInstallIsDisabledAndLoginOnly(): void
    {
        $config = ExtensionConfig::defaults();

        self::assertFalse($config->enabled);
        self::assertSame(AuthMode::LoginOnly, $config->mode);
        self::assertFalse($config->isConfigured());
        self::assertFalse($config->isOperational());
    }

    public function testMissingConfigurationReadsBackAsTheSafeDefaults(): void
    {
        foreach ([null, [], 'not-an-array', 42] as $stored) {
            $config = ExtensionConfig::fromArray($stored);

            self::assertFalse($config->enabled);
            self::assertSame(AuthMode::LoginOnly, $config->mode);
        }
    }

    public function testCorruptedModeFallsBackToLoginOnly(): void
    {
        $config = ExtensionConfig::fromArray([
            'enabled' => true,
            'auth_mode' => 'create-everything',
            'client_id' => 'id',
            'client_secret' => 'secret',
        ]);

        self::assertTrue($config->enabled);
        self::assertSame(AuthMode::LoginOnly, $config->mode, 'An unreadable mode must never enable account creation.');
    }

    public function testTruthyEnabledRepresentations(): void
    {
        foreach ([true, 1, '1', 'true', 'on', 'yes'] as $value) {
            self::assertTrue(ExtensionConfig::fromArray(['enabled' => $value])->enabled, var_export($value, true));
        }

        foreach ([false, 0, '0', 'false', 'off', '', null, 'maybe'] as $value) {
            self::assertFalse(ExtensionConfig::fromArray(['enabled' => $value])->enabled, var_export($value, true));
        }
    }

    public function testOperationalRequiresBothCredentials(): void
    {
        $withoutSecret = ExtensionConfig::fromArray(['enabled' => true, 'client_id' => 'id']);
        self::assertFalse($withoutSecret->isOperational());

        $complete = ExtensionConfig::fromArray(['enabled' => true, 'client_id' => 'id', 'client_secret' => 'secret']);
        self::assertTrue($complete->isOperational());
    }

    public function testAssertOperationalExplainsWhyItIsUnavailable(): void
    {
        $this->expectException(ConfigurationException::class);
        ExtensionConfig::defaults()->assertOperational();
    }

    public function testAssertOperationalRejectsEnabledButUnconfigured(): void
    {
        $config = ExtensionConfig::fromArray(['enabled' => true]);

        try {
            $config->assertOperational();
            self::fail('An enabled but unconfigured extension must not be usable.');
        } catch (ConfigurationException $e) {
            self::assertStringContainsString('not configured correctly', $e->getUserMessage());
        }
    }

    public function testTheAdminViewNeverCarriesTheSecret(): void
    {
        $safe = ExtensionConfig::fromArray([
            'enabled' => true,
            'auth_mode' => 'both',
            'client_id' => 'public-id',
            'client_secret' => 'super-secret-value',
        ])->toSafeArray();

        self::assertArrayNotHasKey('client_secret', $safe);
        self::assertTrue($safe['client_secret_set']);
        self::assertSame('public-id', $safe['client_id']);
        self::assertStringNotContainsString('super-secret-value', json_encode($safe, JSON_THROW_ON_ERROR));
    }

    public function testWithoutSecretStripsTheSecret(): void
    {
        $config = ExtensionConfig::fromArray(['client_id' => 'id', 'client_secret' => 'secret'])->withoutSecret();

        self::assertSame('', $config->clientSecret);
        self::assertSame('id', $config->clientId);
    }

    public function testLinkByVerifiedEmailIsOffByDefault(): void
    {
        self::assertFalse(ExtensionConfig::defaults()->linkByVerifiedEmail);
        self::assertFalse(ExtensionConfig::fromArray([])->linkByVerifiedEmail);
        self::assertFalse(ExtensionConfig::fromArray(['enabled' => true, 'client_id' => 'id', 'client_secret' => 's'])->linkByVerifiedEmail);
    }

    public function testLinkByVerifiedEmailRoundTrips(): void
    {
        $config = ExtensionConfig::fromArray(['link_by_verified_email' => '1']);

        self::assertTrue($config->linkByVerifiedEmail);
        self::assertTrue($config->toArray()['link_by_verified_email']);
        self::assertTrue($config->toSafeArray()['link_by_verified_email']);
        self::assertTrue($config->withoutSecret()->linkByVerifiedEmail, 'Stripping the secret must not silently flip a security setting.');
    }

    public function testAnUnreadableLinkByVerifiedEmailValueFallsBackToOff(): void
    {
        foreach ([null, 'maybe', [], 2, 'off'] as $value) {
            self::assertFalse(
                ExtensionConfig::fromArray(['link_by_verified_email' => $value])->linkByVerifiedEmail,
                var_export($value, true)
            );
        }
    }
}
