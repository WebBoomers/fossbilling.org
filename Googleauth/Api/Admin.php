<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Api;

use Box\Mod\Googleauth\Service;

/**
 * Administrator API.
 *
 * Every call arrives through FOSSBilling's API layer, which has already
 * authenticated the staff member, verified the CSRF token and confirmed the
 * module is active. The per-action staff permission is checked again here, so
 * authorization does not depend on any one caller getting it right.
 *
 * No method in this class ever returns the OAuth client secret.
 */
class Admin extends \FOSSBilling\Api\AbstractApi
{
    /**
     * Current configuration and status for the settings page.
     *
     * @return array<string, mixed>
     */
    public function status(array $data = []): array
    {
        $this->getDi()['mod_service']('Staff')->checkPermissionsAndThrowException(Service::MODULE_NAME, 'view');

        return $this->service()->getStatus();
    }

    /**
     * The exact redirect URI to paste into the Google Cloud Console.
     */
    public function redirect_uri(array $data = []): string
    {
        $this->getDi()['mod_service']('Staff')->checkPermissionsAndThrowException(Service::MODULE_NAME, 'view');

        return $this->service()->getRedirectUri();
    }

    /**
     * Save the settings.
     *
     * @optional bool   $enabled       - turn Google authentication on or off
     * @optional string $auth_mode     - login, signup or both
     * @optional string $client_id     - Google OAuth client ID
     * @optional string $client_secret - Google OAuth client secret; leave empty to keep the stored one
     *
     * @param array<string, mixed> $data
     */
    public function config_update(array $data = []): bool
    {
        $this->getDi()['mod_service']('Staff')->checkPermissionsAndThrowException(Service::MODULE_NAME, 'manage_settings');

        return $this->service()->saveConfig($data);
    }

    /**
     * Delete every Google account connection.
     *
     * Customer accounts, invoices, orders and tickets are not touched: only the
     * ability to sign in with Google is removed.
     *
     * @return int the number of connections deleted
     */
    public function purge_links(array $data = []): int
    {
        $this->getDi()['mod_service']('Staff')->checkPermissionsAndThrowException(Service::MODULE_NAME, 'purge_links');

        return $this->service()->purgeAllLinks();
    }

    private function service(): Service
    {
        /** @var Service $service */
        $service = $this->getService();

        return $service;
    }
}
