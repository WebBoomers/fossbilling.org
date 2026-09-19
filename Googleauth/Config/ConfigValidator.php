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
 * Validates administrator input before anything is written to the database.
 *
 * Nothing submitted is trusted: the mode has to be one of the three known
 * values, credentials have to look like credentials, and enabling the extension
 * without a usable client ID and secret is refused outright rather than leaving
 * a switched-on-but-broken button on the login page.
 */
final class ConfigValidator
{
    /** Google client IDs are URL-safe ASCII; this rejects whitespace and control characters. */
    private const string CLIENT_ID_PATTERN = '/^[A-Za-z0-9._~:@\-]{8,255}$/';

    private const int SECRET_MAX_LENGTH = 512;

    /**
     * @param array<string, mixed> $input          raw submitted data
     * @param string               $existingSecret the secret currently stored, kept when the form leaves the field blank
     *
     * @return array<string, mixed> the sanitized configuration to persist
     *
     * @throws ConfigurationException
     */
    public function validate(array $input, string $existingSecret = ''): array
    {
        $mode = $input[ExtensionConfig::FIELD_MODE] ?? AuthMode::DEFAULT_VALUE;
        if (!AuthMode::isValidValue($mode)) {
            throw new ConfigurationException(
                sprintf('Rejected invalid authentication mode "%s".', is_scalar($mode) ? (string) $mode : gettype($mode)),
                'Please choose one of the available authentication modes: Login Only, Signup Only, or Login & Signup.',
            );
        }

        $clientId = $this->cleanScalar($input[ExtensionConfig::FIELD_CLIENT_ID] ?? '');
        if ($clientId !== '' && preg_match(self::CLIENT_ID_PATTERN, $clientId) !== 1) {
            throw new ConfigurationException(
                'Rejected a client ID that does not look like a Google OAuth client ID.',
                'That does not look like a valid Google OAuth client ID. Copy it exactly from the Google Cloud Console.',
            );
        }

        // An empty secret field means "keep what is stored", so administrators
        // are never forced to re-enter (or re-expose) the existing secret.
        $submittedSecret = $this->cleanScalar($input[ExtensionConfig::FIELD_CLIENT_SECRET] ?? '');
        $clientSecret = $submittedSecret !== '' ? $submittedSecret : $existingSecret;

        if (strlen($clientSecret) > self::SECRET_MAX_LENGTH) {
            throw new ConfigurationException(
                'Rejected an implausibly long client secret.',
                'That client secret is not valid. Copy it exactly from the Google Cloud Console.',
            );
        }

        // Clearing the client ID clears the secret with it: keeping an orphaned
        // secret around serves no purpose.
        if ($clientId === '') {
            $clientSecret = '';
        }

        $enabled = $this->toBool($input[ExtensionConfig::FIELD_ENABLED] ?? false);

        if ($enabled && ($clientId === '' || $clientSecret === '')) {
            throw new ConfigurationException(
                'Refused to enable Google authentication without both a client ID and a client secret.',
                'Add your Google OAuth client ID and client secret before enabling Google authentication.',
            );
        }

        return [
            ExtensionConfig::FIELD_ENABLED => $enabled,
            ExtensionConfig::FIELD_LINK_BY_VERIFIED_EMAIL => $this->toBool($input[ExtensionConfig::FIELD_LINK_BY_VERIFIED_EMAIL] ?? false),
            ExtensionConfig::FIELD_MODE => AuthMode::fromConfigValue($mode)->value,
            ExtensionConfig::FIELD_CLIENT_ID => $clientId,
            ExtensionConfig::FIELD_CLIENT_SECRET => $clientSecret,
        ];
    }

    private function cleanScalar(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }

        // Strip surrounding whitespace and any embedded control characters that
        // a copy/paste from a console might have carried along.
        return trim(preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '');
    }

    private function toBool(mixed $value): bool
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
}
