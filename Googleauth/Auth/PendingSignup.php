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

/**
 * A verified Google identity waiting for the customer to fill in the profile
 * fields this installation requires.
 */
final class PendingSignup
{
    public function __construct(
        public readonly GoogleIdentity $identity,
        public readonly string $returnTo,
        public readonly int $createdAt,
    ) {
    }
}
