<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Auth;

use Box\Mod\Googleauth\Google\GoogleIdentity;
use Box\Mod\Googleauth\Security\SessionStorageInterface;

/**
 * Holds a *verified* Google identity between the callback and the "finish your
 * registration" form, for installations that require profile fields Google
 * cannot supply (country, phone, a custom field, ...).
 *
 * It lives in the server-side session and expires quickly, so the browser never
 * gets to hand back an identity of its own choosing: the completion form posts
 * only the extra profile fields, never the email or the Google subject.
 */
final class PendingSignupStore
{
    public const string SESSION_KEY = 'googleauth_pending_signup';
    public const int LIFETIME_SECONDS = 900;

    public function __construct(private readonly SessionStorageInterface $session)
    {
    }

    public function store(GoogleIdentity $identity, string $returnTo, ?int $now = null): void
    {
        $this->session->set(self::SESSION_KEY, [
            'claims' => [
                'sub' => $identity->subject,
                'email' => $identity->email,
                'email_verified' => $identity->emailVerified,
                'name' => $identity->name,
                'given_name' => $identity->givenName,
                'family_name' => $identity->familyName,
                'picture' => $identity->pictureUrl,
            ],
            'return_to' => $returnTo,
            'created_at' => $now ?? time(),
        ]);
    }

    /**
     * Read without consuming (used to render the form).
     */
    public function peek(?int $now = null): ?PendingSignup
    {
        $now ??= time();
        $raw = $this->session->get(self::SESSION_KEY);

        if (!is_array($raw) || !is_array($raw['claims'] ?? null)) {
            return null;
        }

        $createdAt = is_int($raw['created_at'] ?? null) ? $raw['created_at'] : 0;
        if ($now - $createdAt > self::LIFETIME_SECONDS) {
            $this->clear();

            return null;
        }

        try {
            $identity = GoogleIdentity::fromClaims($raw['claims']);
        } catch (\Throwable) {
            $this->clear();

            return null;
        }

        return new PendingSignup(
            $identity,
            is_string($raw['return_to'] ?? null) ? $raw['return_to'] : '/',
            $createdAt,
        );
    }

    /**
     * Read and remove: a completion form can only ever be submitted once.
     */
    public function consume(?int $now = null): ?PendingSignup
    {
        $pending = $this->peek($now);
        $this->clear();

        return $pending;
    }

    public function clear(): void
    {
        $this->session->delete(self::SESSION_KEY);
    }
}
