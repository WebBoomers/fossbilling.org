<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Auth;

use Box\Mod\Client\Entity\Client;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Support\Log;

/**
 * Signs a customer in exactly the way FOSSBilling's own login does.
 *
 * There is no parallel "Google session": the extension sets the same
 * `client_id` session value the core login sets, after regenerating the session
 * ID, and fires the same events so anything else listening for a client login
 * (notifications, activity log, cart hand-over) still works.
 */
final class SessionAuthenticator
{
    public function __construct(private readonly \Pimple\Container $di)
    {
    }

    /**
     * @return array<string, mixed> the session payload, matching core's login response
     */
    public function login(Client $client): array
    {
        if ($client->getStatus() !== Client::ACTIVE) {
            throw new GoogleAuthException(
                sprintf('Refused to sign in client #%d: the account is not active.', (int) $client->getId()),
                'This account is not active. Please contact support.',
            );
        }

        $ip = $this->di['request']->getClientIp();
        $clientService = $this->di['mod_service']('client');

        $this->di['events_manager']->fire([
            'event' => 'onBeforeClientLogin',
            'params' => ['email' => $client->getEmail(), 'ip' => $ip, 'auth' => 'google'],
        ]);

        $this->di['events_manager']->fire([
            'event' => 'onAfterClientLogin',
            'params' => ['id' => $client->getId(), 'ip' => $ip, 'auth' => 'google'],
        ]);

        // Session fixation defence: the ID the visitor arrived with is retired
        // before the session becomes an authenticated one.
        $oldSessionId = $this->di['session']->getId();
        $this->di['session']->regenerateId();

        $sessionData = $clientService->toSessionArray($client);
        $this->di['session']->set('client_id', $client->getId());
        $this->di['session']->delete('redirect_uri');

        $this->queueLocaleCookie($client);
        $this->transferCart($oldSessionId);

        Log::info($this->di, 'Client #{client_id} logged in with Google', ['client_id' => $client->getId()]);

        return $sessionData;
    }

    private function queueLocaleCookie(Client $client): void
    {
        $lang = $client->getLang();
        if (empty($lang) || !isset($this->di['cookie_queue'])) {
            return;
        }

        try {
            $this->di['cookie_queue']->queue(\FOSSBilling\Http\CookieNames::LOCALE, $lang, strtotime('+1 month'), '/');
        } catch (\Throwable $e) {
            Log::debug($this->di, 'Could not queue the locale cookie: ' . $e->getMessage());
        }
    }

    private function transferCart(string $oldSessionId): void
    {
        try {
            $this->di['mod_service']('cart')->transferFromOtherSession($oldSessionId);
        } catch (\Throwable $e) {
            // A cart that cannot be carried over is not a reason to fail a login.
            Log::debug($this->di, 'Could not transfer the cart after a Google login: ' . $e->getMessage());
        }
    }
}
