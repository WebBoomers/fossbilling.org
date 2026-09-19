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
 * Customer API.
 *
 * FOSSBilling's API layer authenticates the customer and validates the CSRF
 * token before any of these run, so the only thing left to enforce here is that
 * a customer can act on nothing but their own connection: the client ID comes
 * from the authenticated identity, never from the request.
 */
class Client extends \FOSSBilling\Api\AbstractApi
{
    /**
     * @return array<string, mixed>
     */
    public function status(array $data = []): array
    {
        return $this->service()->getClientLinkStatus($this->clientId());
    }

    /**
     * Disconnect Google from the signed-in customer's account.
     *
     * The customer account, its invoices, orders and tickets are untouched. The
     * call is refused if it would leave the customer with no way back in.
     */
    public function disconnect(array $data = []): bool
    {
        return $this->service()->disconnect($this->clientId());
    }

    private function clientId(): int
    {
        $identity = $this->getIdentity();

        if (!$identity instanceof \Box\Mod\Client\Entity\Client) {
            throw new \FOSSBilling\InformationException('Authentication Failed', null, 201);
        }

        return (int) $identity->getId();
    }

    private function service(): Service
    {
        /** @var Service $service */
        $service = $this->getService();

        return $service;
    }
}
