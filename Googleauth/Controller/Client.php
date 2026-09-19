<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Controller;

use Box\Mod\Googleauth\Auth\AuthenticationFlow;
use Box\Mod\Googleauth\Auth\FlowResult;
use Box\Mod\Googleauth\Auth\PendingSignup;
use Box\Mod\Googleauth\Enum\FlowIntent;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Security\ReturnUrlGuard;
use Box\Mod\Googleauth\Service;
use Symfony\Component\HttpFoundation\Response;
use Box\Mod\Googleauth\Support\Log;

/**
 * The customer-facing routes.
 *
 * These are the only public entry points the extension adds:
 *
 *   GET /googleauth/login     start a sign-in
 *   GET /googleauth/signup    start a registration
 *   GET /googleauth/link      connect Google to the signed-in account (CSRF checked)
 *   GET /googleauth/callback  Google redirects back here
 *   GET /googleauth/complete  finish a registration that needs more profile fields
 *   GET /googleauth/account   the customer's Google connection page
 *
 * Normal FOSSBilling login, registration and password reset are untouched and
 * keep working whether or not this module is installed, enabled or reachable.
 */
class Client implements \FOSSBilling\InjectionAwareInterface
{
    protected ?\Pimple\Container $di = null;

    public function setDi(\Pimple\Container $di): void
    {
        $this->di = $di;
    }

    public function getDi(): ?\Pimple\Container
    {
        return $this->di;
    }

    public function register(\Box_App &$app): void
    {
        $app->get('/googleauth/login', 'get_login', [], static::class);
        $app->get('/googleauth/signup', 'get_signup', [], static::class);
        $app->get('/googleauth/link', 'get_link', [], static::class);
        $app->get('/googleauth/callback', 'get_callback', [], static::class);
        $app->get('/googleauth/complete', 'get_complete', [], static::class);
        $app->get('/googleauth/account', 'get_account', [], static::class);
    }

    public function get_login(\Box_App $app): Response
    {
        return $this->start($app, FlowIntent::Login);
    }

    public function get_signup(\Box_App $app): Response
    {
        return $this->start($app, FlowIntent::Signup);
    }

    public function get_link(\Box_App $app): Response
    {
        if ($response = $this->guardInactive($app)) {
            return $response;
        }

        $service = $this->service();

        try {
            // Connecting an account changes state, so the request carries
            // FOSSBilling's own CSRF token and is rejected without it.
            $service->assertCsrfToken($this->di['request']->query->get('CSRFToken'));
        } catch (GoogleAuthException $e) {
            return $this->fail($app, $e, AuthenticationFlow::PROFILE_PATH);
        }

        return $this->start($app, FlowIntent::Link);
    }

    public function get_callback(\Box_App $app): Response
    {
        if ($response = $this->guardInactive($app)) {
            return $response;
        }

        try {
            $result = $this->service()->handleCallback($this->di['request']->query->all());
        } catch (GoogleAuthException $e) {
            return $this->fail($app, $e, AuthenticationFlow::LOGIN_PATH);
        } catch (\Throwable $e) {
            Log::error($this->di, 'Unexpected failure while handling the Google callback: ' . $e->getMessage());

            return $this->redirectWithMessage(
                $app,
                AuthenticationFlow::LOGIN_PATH,
                'Google authentication could not be completed. Please try again or use your usual login details.'
            );
        }

        return $this->finish($app, $result);
    }

    /**
     * The "we need a few more details" step, shown only when this installation
     * requires profile fields that a Google identity cannot supply.
     */
    public function get_complete(\Box_App $app): string|Response
    {
        if ($response = $this->guardInactive($app)) {
            return $response;
        }

        $service = $this->service();
        $pending = $service->peekPendingSignup();

        if (!$pending instanceof PendingSignup) {
            return $this->redirectWithMessage($app, AuthenticationFlow::SIGNUP_PATH, 'This sign-up has expired. Please start again.');
        }

        return $app->render('mod_googleauth_complete', [
            'google_email' => $pending->identity->email,
            'google_name' => $pending->identity->name,
            'fields' => $service->getPendingSignupFields($pending),
        ]);
    }

    public function get_account(\Box_App $app): string|Response
    {
        if ($response = $this->guardInactive($app)) {
            return $response;
        }

        // Throws/redirects through FOSSBilling's own client authentication guard.
        $this->di['is_client_logged'];

        $clientId = (int) $this->di['session']->get('client_id');

        return $app->render('mod_googleauth_account', [
            'googleauth' => $this->service()->getClientLinkStatus($clientId),
        ]);
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    private function start(\Box_App $app, FlowIntent $intent): Response
    {
        if ($response = $this->guardInactive($app)) {
            return $response;
        }

        $fallback = $intent === FlowIntent::Link ? AuthenticationFlow::PROFILE_PATH : AuthenticationFlow::LOGIN_PATH;

        try {
            $authorizationUrl = $this->service()->createAuthorizationUrl(
                $intent,
                $this->di['request']->query->get('redirect')
            );
        } catch (GoogleAuthException $e) {
            return $this->fail($app, $e, $fallback);
        } catch (\Throwable $e) {
            Log::error($this->di, 'Could not start the Google authentication flow: ' . $e->getMessage());

            return $this->redirectWithMessage($app, $fallback, 'Google sign-in is unavailable right now. Please use your usual login details.');
        }

        // Straight to Google; nothing about the flow is exposed to the browser
        // beyond the opaque state value in the URL.
        return $app->redirectUrl($authorizationUrl);
    }

    private function finish(\Box_App $app, FlowResult $result): Response
    {
        if ($result->hasMessage()) {
            $this->setPendingMessage($result->message);
        }

        return $this->leaveTheCrossSiteChain($result->redirectPath);
    }

    private function fail(\Box_App $app, GoogleAuthException $e, string $fallbackPath): Response
    {
        // The technical detail goes to the log; the visitor sees the neutral
        // sentence carried on the exception.
        Log::warning($this->di, $e->getMessage());

        return $this->redirectWithMessage($app, $fallbackPath, $e->getUserMessage(), $e->getUserMessageParams());
    }

    /**
     * @param array<string, string> $params
     */
    private function redirectWithMessage(\Box_App $app, string $path, string $message, array $params = []): Response
    {
        $this->setPendingMessage($message, $params);

        return $this->leaveTheCrossSiteChain($path);
    }

    /**
     * Hand the browser a tiny page that redirects itself, instead of a 302.
     *
     * FOSSBilling marks its session cookie `SameSite=Strict`. A browser withholds
     * a Strict cookie from *every* request in a redirect chain that began
     * cross-site - so a plain 302 from this callback to the dashboard arrives
     * without the session that was just established, and the customer lands
     * looking signed out (and never sees the queued message, which also lives in
     * that session).
     *
     * A navigation started by a document on our own origin is same-site, and does
     * carry the cookie. So the callback returns a document whose only job is to
     * navigate: `<meta refresh>` covers browsers without JavaScript, the script
     * makes it instant, and the link is there if both are blocked.
     */
    private function leaveTheCrossSiteChain(string $path): Response
    {
        $url = $this->di['url']->link(ReturnUrlGuard::toLinkPath($path));
        $escaped = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
        $message = htmlspecialchars(__trans('Signing you in...'), ENT_QUOTES, 'UTF-8');
        $link = htmlspecialchars(__trans('Continue'), ENT_QUOTES, 'UTF-8');

        $html = '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<meta name="robots" content="noindex">'
            . '<meta http-equiv="refresh" content="0;url=' . $escaped . '">'
            . '<title>' . $message . '</title></head>'
            . '<body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;padding:2rem;text-align:center">'
            . '<p>' . $message . ' <a href="' . $escaped . '">' . $link . '</a></p>'
            . '<script>window.location.replace(' . json_encode($url, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ');</script>'
            . '</body></html>';

        return new Response($html, 200, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store, no-cache, must-revalidate',
            'Referrer-Policy' => 'no-referrer',
        ]);
    }

    /**
     * @param array<string, string> $params
     */
    private function setPendingMessage(string $message, array $params = []): void
    {
        try {
            $this->di['mod_service']('system')->setPendingMessage(__trans($message, $params === [] ? null : $params));
        } catch (\Throwable $e) {
            Log::debug($this->di, 'Could not queue a message for the visitor: ' . $e->getMessage());
        }
    }

    /**
     * Module files can exist on disk while the extension is deactivated, so
     * every route confirms the extension is actually active first.
     */
    private function guardInactive(\Box_App $app): ?Response
    {
        if ($this->di['mod_service']('extension')->isExtensionActive('mod', Service::MODULE_NAME)) {
            return null;
        }

        return $app->redirect('');
    }

    private function service(): Service
    {
        /** @var Service $service */
        $service = $this->di['mod_service'](Service::MODULE_NAME);

        return $service;
    }
}
