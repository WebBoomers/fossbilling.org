<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Config;

use Box\Mod\Googleauth\Enum\AuthMode;
use Box\Mod\Googleauth\Exception\ConfigurationException;

/**
 * Typed view over the module configuration that FOSSBilling stores (encrypted)
 * in `extension_meta`.
 *
 * The defaults are the whole point of this class: an installation that has never
 * been configured reads back as "disabled, Login Only".
 */
final class ExtensionConfig
{
    public const string EXTENSION_KEY = 'mod_googleauth';

    public const string FIELD_ENABLED = 'enabled';
    public const string FIELD_MODE = 'auth_mode';
    public const string FIELD_CLIENT_ID = 'client_id';
    public const string FIELD_CLIENT_SECRET = 'client_secret';

    /**
     * Opt-in: sign a customer in when Google reports a verified email address
     * that matches theirs, even though no Google identity has ever been linked
     * to that account.
     *
     * Off by default, and deliberately so. Google's `email_verified` means
     * Google verified the address, not that its holder is your customer. For
     * gmail.com that is a strong claim - Google owns the mailbox and does not
     * recycle addresses. For a custom domain it is much weaker: whoever controls
     * the domain can create a Google Workspace tenant and mint any address on
     * it, fully "verified". A Workspace administrator at the customer's own
     * company, or anyone who picks up the domain after it lapses, could then
     * sign straight into that customer's billing account without ever knowing
     * the password.
     *
     * Turning this on trades that risk for convenience. The safe path - which
     * remains the default - is for the customer to sign in once with their
     * password and connect Google from their account page.
     */
    public const string FIELD_LINK_BY_VERIFIED_EMAIL = 'link_by_verified_email';

    private function __construct(
        public readonly bool $enabled,
        public readonly AuthMode $mode,
        public readonly string $clientId,
        public readonly string $clientSecret,
        public readonly bool $linkByVerifiedEmail = false,
    ) {
    }

    /**
     * Safe defaults, used for a fresh install and whenever stored configuration
     * is missing or unreadable.
     */
    public static function defaults(): self
    {
        return new self(false, AuthMode::LoginOnly, '', '');
    }

    /**
     * @param array<string, mixed>|mixed $config
     */
    public static function fromArray(mixed $config): self
    {
        if (!is_array($config)) {
            return self::defaults();
        }

        return new self(
            self::toBool($config[self::FIELD_ENABLED] ?? false),
            AuthMode::fromConfigValue($config[self::FIELD_MODE] ?? null),
            self::toTrimmedString($config[self::FIELD_CLIENT_ID] ?? ''),
            self::toTrimmedString($config[self::FIELD_CLIENT_SECRET] ?? ''),
            self::toBool($config[self::FIELD_LINK_BY_VERIFIED_EMAIL] ?? false),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            self::FIELD_ENABLED => $this->enabled,
            self::FIELD_MODE => $this->mode->value,
            self::FIELD_CLIENT_ID => $this->clientId,
            self::FIELD_CLIENT_SECRET => $this->clientSecret,
            self::FIELD_LINK_BY_VERIFIED_EMAIL => $this->linkByVerifiedEmail,
        ];
    }

    /**
     * The administrator-facing view. The client secret is never included - only
     * whether one is stored.
     *
     * @return array<string, mixed>
     */
    public function toSafeArray(): array
    {
        return [
            self::FIELD_ENABLED => $this->enabled,
            self::FIELD_MODE => $this->mode->value,
            'auth_mode_label' => $this->mode->label(),
            self::FIELD_CLIENT_ID => $this->clientId,
            'client_secret_set' => $this->clientSecret !== '',
            self::FIELD_LINK_BY_VERIFIED_EMAIL => $this->linkByVerifiedEmail,
            'configured' => $this->isConfigured(),
            'operational' => $this->isOperational(),
        ];
    }

    public function isConfigured(): bool
    {
        return $this->clientId !== '' && $this->clientSecret !== '';
    }

    /**
     * Switched on *and* usable. Everything customer-facing checks this.
     */
    public function isOperational(): bool
    {
        return $this->enabled && $this->isConfigured();
    }

    /**
     * @throws ConfigurationException when a customer-facing flow is started but the extension cannot serve it
     */
    public function assertOperational(): void
    {
        if (!$this->enabled) {
            throw new ConfigurationException(
                'Google authentication is disabled in the extension settings.',
                'Google sign-in is not available on this site.',
            );
        }

        if (!$this->isConfigured()) {
            throw new ConfigurationException(
                'Google authentication is enabled but the OAuth client ID and/or client secret are missing.',
                'Google sign-in is not configured correctly on this site. Please contact support.',
            );
        }
    }

    public function withoutSecret(): self
    {
        return new self($this->enabled, $this->mode, $this->clientId, '', $this->linkByVerifiedEmail);
    }

    private static function toBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value === 1;
        }

        if (is_string($value)) {
            return in_array(strtolower(trim($value)), ['1', 'true', 'on', 'yes'], true);
        }

        return false;
    }

    private static function toTrimmedString(mixed $value): string
    {
        return is_string($value) ? trim($value) : '';
    }
}
