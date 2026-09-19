<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Api;

use Box\Mod\Googleauth\Auth\FlowResult;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Service;
use Box\Mod\Googleauth\Support\Log;

/**
 * Guest API.
 *
 * Only two things are exposed to unauthenticated visitors: whether (and where)
 * to draw the buttons, and the final step of a registration that needed extra
 * profile fields. Neither returns anything sensitive - in particular the OAuth
 * client secret is never readable from this role.
 */
class Guest extends \FOSSBilling\Api\AbstractApi
{
    /**
     * Drives the login/signup button widgets.
     *
     * @return array<string, mixed>
     */
    public function button_context(array $data = []): array
    {
        return $this->service()->getButtonContext();
    }

    /**
     * Finish a Google registration that required profile fields Google cannot
     * supply (country, phone, a custom field, ...).
     *
     * The verified Google identity is taken from the server-side session, so the
     * submitted form can only ever add profile data - never change who is being
     * registered. FOSSBilling's own CSRF token is required because the guest API
     * is not CSRF-checked by the framework.
     *
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>
     */
    public function complete_signup(array $data = []): array
    {
        $service = $this->service();

        try {
            $service->assertCsrfToken($data['CSRFToken'] ?? $this->getDi()['request']->request->get('CSRFToken'));

            $result = $service->completePendingSignup($data);
        } catch (GoogleAuthException $e) {
            Log::warning($this->getDi(), $e->getMessage());
            $service->clearPendingSignup();

            throw new \FOSSBilling\InformationException($e->getUserMessage());
        }

        if ($result->type === FlowResult::TYPE_ERROR) {
            throw new \FOSSBilling\InformationException($result->message);
        }

        return [
            'result' => true,
            'redirect' => $result->redirectPath,
        ];
    }

    private function service(): Service
    {
        /** @var Service $service */
        $service = $this->getService();

        return $service;
    }
}
