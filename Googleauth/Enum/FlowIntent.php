<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Enum;

/**
 * What the visitor was trying to do when the OAuth flow started.
 *
 * The intent is stored server-side with the OAuth state and is never read back
 * from the callback query string, so a tampered callback cannot turn a "login"
 * attempt into an account creation.
 */
enum FlowIntent: string
{
    /** Authenticate an existing customer who has already linked Google. */
    case Login = 'login';

    /** Create a new FOSSBilling customer from a Google identity. */
    case Signup = 'signup';

    /** Attach a Google identity to the customer who is already signed in. */
    case Link = 'link';

    public static function tryFromValue(mixed $value): ?self
    {
        if ($value instanceof self) {
            return $value;
        }

        return is_string($value) ? self::tryFrom($value) : null;
    }
}
