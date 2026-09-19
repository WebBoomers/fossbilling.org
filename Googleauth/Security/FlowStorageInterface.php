<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Security;

/**
 * Where pending OAuth flows are kept between the authorization request and the
 * callback.
 *
 * Not the PHP session: FOSSBilling marks its session cookie `SameSite=Strict` by
 * default, and browsers withhold Strict cookies on the top-level navigation back
 * from Google, so a session-backed flow is invisible to the callback.
 */
interface FlowStorageInterface
{
    public function put(FlowState $state, int $ttlSeconds): void;

    /**
     * Fetch the flow for this state value and remove it in the same breath.
     *
     * Removing before the caller validates anything is what makes a flow
     * single-use: a replayed callback finds nothing left to match against.
     */
    public function take(string $state): ?FlowState;

    /**
     * Discard a pending flow without consuming it (used when Google reports an
     * error, so nothing is left dangling).
     */
    public function discard(string $state): void;
}
