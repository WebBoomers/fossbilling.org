<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Security;

use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\OAuth\StateToken;

/**
 * Issues and consumes the single pending OAuth flow for a browser.
 *
 * Three things have to line up before a callback is accepted:
 *
 *  1. the `state` in the URL must match a stored flow (and that flow is deleted
 *     on read, so it can only ever be used once);
 *  2. the correlation token in the browser's `SameSite=Lax` cookie must match
 *     the one issued when the flow started - this is what stops an attacker
 *     completing a Google sign-in themselves and then walking a victim's browser
 *     through the resulting callback URL to log them into the attacker's account;
 *  3. the flow must not have expired.
 */
final class FlowStateStore
{
    /** Name of the SameSite=Lax cookie that binds a flow to one browser. */
    public const string COOKIE_NAME = 'googleauth_flow';

    /** A flow the visitor has not completed within this many seconds is dead. */
    public const int LIFETIME_SECONDS = 600;

    public function __construct(private readonly FlowStorageInterface $storage)
    {
    }

    public function store(FlowState $state): void
    {
        $this->storage->put($state, self::LIFETIME_SECONDS);
    }

    public function discard(mixed $state): void
    {
        if (is_string($state) && $state !== '') {
            $this->storage->discard($state);
        }
    }

    /**
     * Consume the pending flow and validate the callback against it.
     *
     * @param mixed $providedState       the `state` query parameter
     * @param mixed $providedCorrelation the value of the correlation cookie
     *
     * @throws GoogleAuthException when the state is missing, unknown, replayed, expired, or from another browser
     */
    public function consume(mixed $providedState, mixed $providedCorrelation, ?int $now = null): FlowState
    {
        $now ??= time();

        if (!is_string($providedState) || !StateToken::isWellFormed($providedState)) {
            throw new GoogleAuthException(
                'OAuth callback arrived with a missing or malformed state value.',
                'This Google sign-in request could not be verified. Please start again.',
            );
        }

        // Fetching removes the record, so failing any check below still burns
        // the flow.
        $stored = $this->storage->take($providedState);

        if (!$stored instanceof FlowState) {
            throw new GoogleAuthException(
                'OAuth callback received with no matching pending flow (unknown, already used or expired state).',
                'This Google sign-in link has expired or was already used. Please start again.',
            );
        }

        if (!StateToken::matches($stored->state, $providedState)) {
            throw new GoogleAuthException(
                'OAuth state mismatch: the value returned by the callback does not match the value issued for this flow.',
                'This Google sign-in request could not be verified. Please start again.',
            );
        }

        if (!$stored->matchesCorrelation($providedCorrelation)) {
            throw new GoogleAuthException(
                'OAuth correlation cookie missing or mismatched: the callback did not come from the browser that started the flow.',
                'This Google sign-in could not be verified in this browser. Please start again, and make sure cookies are enabled.',
            );
        }

        if ($stored->isExpired($now, self::LIFETIME_SECONDS)) {
            throw new GoogleAuthException(
                'OAuth state expired before the callback was received.',
                'This Google sign-in link has expired or was already used. Please start again.',
            );
        }

        return $stored;
    }
}
