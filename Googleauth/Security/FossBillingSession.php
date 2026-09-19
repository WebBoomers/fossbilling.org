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
 * Adapter over FOSSBilling's session service.
 *
 * Everything this extension keeps between the authorization request and the
 * callback lives here - in the server-side session - and never in a cookie, a
 * hidden form field or the URL.
 */
final class FossBillingSession implements SessionStorageInterface
{
    public function __construct(private readonly \FOSSBilling\Session $session)
    {
    }

    public function get(string $key): mixed
    {
        return $this->session->get($key);
    }

    public function set(string $key, mixed $value): void
    {
        $this->session->set($key, $value);
    }

    public function delete(string $key): void
    {
        $this->session->delete($key);
    }
}
