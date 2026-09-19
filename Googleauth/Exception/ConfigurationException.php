<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Exception;

/**
 * Raised when the extension is switched on but cannot work: missing client ID,
 * missing client secret, or an invalid authentication mode.
 */
class ConfigurationException extends GoogleAuthException
{
}
