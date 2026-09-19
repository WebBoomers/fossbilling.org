<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Google;

use Box\Mod\Googleauth\Exception\GoogleAuthException;

/**
 * A verified Google end user.
 *
 * `sub` is the only stable identifier. An email address can be changed, released
 * and re-registered, so it is kept purely as metadata and is never used to
 * decide *which* FOSSBilling customer an identity belongs to.
 */
final class GoogleIdentity
{
    private function __construct(
        public readonly string $subject,
        public readonly string $email,
        public readonly bool $emailVerified,
        public readonly ?string $name,
        public readonly ?string $givenName,
        public readonly ?string $familyName,
        public readonly ?string $pictureUrl,
    ) {
    }

    /**
     * @param array<string, mixed> $claims verified ID token claims
     */
    public static function fromClaims(array $claims): self
    {
        $subject = self::stringClaim($claims, 'sub');
        if ($subject === null) {
            throw new GoogleAuthException('Verified ID token is missing the sub claim.');
        }

        $email = self::stringClaim($claims, 'email');
        if ($email === null) {
            // Without an email there is no way to create or describe a customer
            // account, so the flow stops rather than inventing one.
            throw new GoogleAuthException(
                'Verified ID token contains no email address.',
                'Your Google account did not share an email address, which is required here. Please use a Google account with an email address, or sign in with your usual details.',
            );
        }

        $verified = $claims['email_verified'] ?? false;
        $emailVerified = $verified === true || $verified === 'true' || $verified === 1 || $verified === '1';

        return new self(
            $subject,
            strtolower($email),
            $emailVerified,
            self::stringClaim($claims, 'name'),
            self::stringClaim($claims, 'given_name'),
            self::stringClaim($claims, 'family_name'),
            self::stringClaim($claims, 'picture'),
        );
    }

    /**
     * The extension refuses to act on an unverified address: an attacker who can
     * set an arbitrary unverified email on a throwaway Google account would
     * otherwise be able to aim a flow at somebody else's address.
     */
    public function assertEmailVerified(): void
    {
        if (!$this->emailVerified) {
            throw new GoogleAuthException(
                'Google reported the email address on this identity as unverified.',
                'Google has not verified the email address on that account. Please verify it with Google and try again.',
            );
        }
    }

    public function firstName(): string
    {
        $candidate = $this->givenName ?? $this->name;
        if (is_string($candidate) && trim($candidate) !== '') {
            return trim($candidate);
        }

        $localPart = strstr($this->email, '@', true);

        return is_string($localPart) && $localPart !== '' ? $localPart : 'Customer';
    }

    public function lastName(): ?string
    {
        if (is_string($this->familyName) && trim($this->familyName) !== '') {
            return trim($this->familyName);
        }

        return null;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function stringClaim(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;
        if (!is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
