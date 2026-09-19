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
 * The three session operations this extension needs.
 *
 * FOSSBilling's own \FOSSBilling\Session already exposes exactly these, so the
 * adapter is a pass-through; the interface exists so the OAuth flow state can be
 * unit tested without booting the application.
 */
interface SessionStorageInterface
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value): void;

    public function delete(string $key): void;
}
