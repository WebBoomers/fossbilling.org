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
use Box\Mod\Googleauth\Config\ExtensionConfig;
use Box\Mod\Googleauth\Entity\GoogleAccount;
use Box\Mod\Googleauth\Enum\FlowIntent;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Google\GoogleIdentity;
use Box\Mod\Googleauth\Security\FlowState;
use Box\Mod\Googleauth\Support\Log;

/**
 * Decides what a verified Google identity means for this installation.
 *
 * This is where the account takeover rules live, so they can be read in one
 * place:
 *
 *  - A customer is identified by the Google `sub` recorded in the mapping table.
 *    A matching email address is never sufficient and never creates or claims a
 *    customer.
 *  - Linking is only ever performed for a customer who is already signed in to
 *    FOSSBilling during that same request.
 *  - A signup whose email already belongs to a customer is refused; the visitor
 *    is told to sign in normally and connect Google from their profile.
 *  - The intent (login / signup / link) comes from the server-side flow state,
 *    never from the callback query string, and is checked against the
 *    administrator's chosen authentication mode before anything happens.
 */
final class AuthenticationFlow
{
    public const string LOGIN_PATH = '/login';
    public const string SIGNUP_PATH = '/signup';
    public const string PROFILE_PATH = '/googleauth/account';
    public const string COMPLETE_PATH = '/googleauth/complete';

    public function __construct(
        private readonly \Pimple\Container $di,
        private readonly ExtensionConfig $config,
        private readonly AccountLinker $linker,
        private readonly CustomerProvisioner $provisioner,
        private readonly SessionAuthenticator $authenticator,
        private readonly PendingSignupStore $pendingSignups,
    ) {
    }

    public function handle(FlowState $state, GoogleIdentity $identity): FlowResult
    {
        $identity->assertEmailVerified();

        return match ($state->intent) {
            FlowIntent::Link => $this->handleLink($state, $identity),
            FlowIntent::Login => $this->handleLogin($state, $identity),
            FlowIntent::Signup => $this->handleSignup($state, $identity),
        };
    }

    // -----------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------

    private function handleLogin(FlowState $state, GoogleIdentity $identity): FlowResult
    {
        if (!$this->config->mode->allowsLogin() && !$this->config->mode->allowsSignup()) {
            return FlowResult::error(self::LOGIN_PATH, 'Google sign-in is not available on this site.');
        }

        $link = $this->linker->findBySubject($identity->subject);
        if ($link instanceof GoogleAccount) {
            return $this->signIn($link, $identity, $state->returnTo);
        }

        // Opt-in only: sign in an existing customer whose address matches the
        // verified Google address, without a prior link.
        $adopted = $this->adoptByVerifiedEmail($identity, $state->returnTo);
        if ($adopted instanceof FlowResult) {
            return $adopted;
        }

        // Login & Signup mode lets an unknown Google identity continue into the
        // signup path; Login Only stops here without creating anything.
        if ($this->config->mode->allowsSignup()) {
            return $this->handleSignup($state, $identity);
        }

        Log::info($this->di, 'Google sign-in attempt for an identity that is not linked to any customer.');

        return FlowResult::error(
            self::LOGIN_PATH,
            'No account here is linked to that Google account. Sign in with your usual details and connect Google from your profile, or create an account first.',
        );
    }

    // -----------------------------------------------------------------
    // Signup
    // -----------------------------------------------------------------

    private function handleSignup(FlowState $state, GoogleIdentity $identity): FlowResult
    {
        // An identity that is already linked simply signs in; clicking "Sign up
        // with Google" twice must not create a second customer.
        $link = $this->linker->findBySubject($identity->subject);
        if ($link instanceof GoogleAccount) {
            return $this->signIn($link, $identity, $state->returnTo);
        }

        if (!$this->config->mode->allowsSignup()) {
            return FlowResult::error(
                self::LOGIN_PATH,
                'Creating an account with Google is not available on this site. Please register first, then connect Google from your profile.',
            );
        }

        if (!$this->provisioner->signupAllowed()) {
            return FlowResult::error(self::SIGNUP_PATH, 'New registrations are temporarily disabled on this site.');
        }

        if ($this->provisioner->emailAlreadyRegistered($identity->email)) {
            $adopted = $this->adoptByVerifiedEmail($identity, $state->returnTo);
            if ($adopted instanceof FlowResult) {
                return $adopted;
            }

            // Deliberately not linked automatically: proving control of an email
            // address at Google is not proof of ownership of an account that was
            // created here with that address.
            Log::info($this->di, 'Google signup refused: an account already exists for the address on the Google identity.');

            return FlowResult::error(
                self::LOGIN_PATH,
                'An account with that email address already exists here. Please sign in with your usual details, then connect Google from your profile.',
            );
        }

        $missing = $this->provisioner->missingRequiredFields($identity);
        if ($missing !== []) {
            // Rather than creating an incomplete customer, park the verified
            // identity and ask for the remaining fields.
            $this->pendingSignups->store($identity, $state->returnTo);

            return FlowResult::info(self::COMPLETE_PATH, 'Please complete a few more details to finish creating your account.');
        }

        return $this->createAndSignIn($identity, [], $state->returnTo);
    }

    /**
     * Finish a signup that needed extra profile fields.
     *
     * @param array<string, mixed> $fields
     */
    public function completeSignup(PendingSignup $pending, array $fields): FlowResult
    {
        $identity = $pending->identity;

        if (!$this->config->mode->allowsSignup()) {
            throw new GoogleAuthException(
                'Signup completion refused: the authentication mode no longer allows signup.',
                'Creating an account with Google is not available on this site.',
            );
        }

        if ($this->linker->findBySubject($identity->subject) instanceof GoogleAccount) {
            throw new GoogleAuthException(
                'Signup completion refused: the Google identity was linked while the form was open.',
                'That Google account is already connected to an account on this site. Please sign in instead.',
            );
        }

        if ($this->provisioner->emailAlreadyRegistered($identity->email)) {
            throw new GoogleAuthException(
                'Signup completion refused: an account with that email address now exists.',
                'An account with that email address already exists here. Please sign in with your usual details, then connect Google from your profile.',
            );
        }

        return $this->createAndSignIn($identity, $fields, $pending->returnTo);
    }

    /**
     * @param array<string, mixed> $fields
     */
    private function createAndSignIn(GoogleIdentity $identity, array $fields, string $returnTo): FlowResult
    {
        $client = $this->provisioner->create($identity, $fields);
        $clientId = (int) $client->getId();

        try {
            $this->linker->link($clientId, $identity);
        } catch (\Throwable $e) {
            // The customer exists but has no Google link. Leaving it silently
            // would strand the account, so make the failure visible and
            // recoverable: the customer can reset their password and connect
            // Google from their profile.
            Log::error($this->di, 'Created client #{client_id} from a Google identity but could not store the link: {error}', [
                'client_id' => $clientId,
                'error' => $e->getMessage(),
            ]);

            return FlowResult::error(
                self::LOGIN_PATH,
                'Your account was created, but it could not be connected to Google. Please use "Forgot password" to set a password and sign in.',
            );
        }

        $this->authenticator->login($client);

        return FlowResult::success($returnTo, 'Welcome! Your account has been created with Google.');
    }

    // -----------------------------------------------------------------
    // Linking
    // -----------------------------------------------------------------

    private function handleLink(FlowState $state, GoogleIdentity $identity): FlowResult
    {
        $currentClientId = $this->currentClientId();

        if ($currentClientId === null || $state->clientId === null || $currentClientId !== $state->clientId) {
            // Either the session ended, or the browser that started the link is
            // not the one that came back. Neither may result in a link.
            Log::warning($this->di, 'Google account linking aborted: the signed-in customer changed during the flow.');

            return FlowResult::error(self::LOGIN_PATH, 'Please sign in again before connecting your Google account.');
        }

        $existing = $this->linker->findBySubject($identity->subject);
        if ($existing instanceof GoogleAccount) {
            if ($existing->getClientId() === $currentClientId) {
                return FlowResult::info(self::PROFILE_PATH, 'That Google account is already connected to your account.');
            }

            Log::warning($this->di, 'Refused to connect a Google identity that is already linked to a different customer.');

            return FlowResult::error(self::PROFILE_PATH, 'That Google account is already connected to another account on this site.');
        }

        if ($this->linker->findByClientId($currentClientId) instanceof GoogleAccount) {
            return FlowResult::error(self::PROFILE_PATH, 'Your account is already connected to a Google account. Disconnect it first if you want to use a different one.');
        }

        $this->linker->link($currentClientId, $identity);

        return FlowResult::success(self::PROFILE_PATH, 'Your Google account has been connected.');
    }

    // -----------------------------------------------------------------
    // Shared
    // -----------------------------------------------------------------

    /**
     * Claim an existing customer by verified email address, when the
     * administrator has explicitly allowed it.
     *
     * This is the one path in the extension where a customer is identified by
     * something other than a previously linked Google `sub`, and it exists only
     * because some operators want it. It is gated on:
     *
     *  - the `link_by_verified_email` setting being switched on (off by default);
     *  - Google reporting the address as verified;
     *  - exactly one active customer holding that address - an ambiguous match
     *    is never resolved by guessing.
     *
     * The risk this accepts is documented on
     * {@see ExtensionConfig::FIELD_LINK_BY_VERIFIED_EMAIL}: a verified Google
     * address on a custom domain only proves control of that domain, not
     * ownership of the billing account. Every use is logged as a security event
     * so it can be audited after the fact.
     */
    private function adoptByVerifiedEmail(GoogleIdentity $identity, string $returnTo): ?FlowResult
    {
        if (!$this->config->linkByVerifiedEmail || !$identity->emailVerified) {
            return null;
        }

        $client = $this->linker->findActiveClientByEmail($identity->email);
        if (!$client instanceof Client) {
            return null;
        }

        $clientId = (int) $client->getId();

        try {
            $link = $this->linker->link($clientId, $identity);
        } catch (GoogleAuthException $e) {
            Log::warning($this->di, 'Could not claim client #{client_id} by verified email: {error}', [
                'client_id' => $clientId,
                'error' => $e->getMessage(),
            ]);

            return null;
        }

        Log::warning($this->di, 'Connected a Google account to client #{client_id} by verified email match alone, because "link by verified email" is enabled. No password was required.', [
            'client_id' => $clientId,
        ]);

        $this->authenticator->login($client);
        $this->linker->recordLogin($link, $identity);

        return FlowResult::success($returnTo, 'You are signed in. Your Google account is now connected to this account.');
    }

    private function signIn(GoogleAccount $link, GoogleIdentity $identity, string $returnTo): FlowResult
    {
        $client = $this->linker->findClientForSubject($identity->subject);

        if (!$client instanceof Client) {
            return FlowResult::error(
                self::LOGIN_PATH,
                'No account here is linked to that Google account. Sign in with your usual details and connect Google from your profile, or create an account first.',
            );
        }

        $this->authenticator->login($client);
        $this->linker->recordLogin($link, $identity);

        return FlowResult::success($returnTo, 'You are signed in.');
    }

    private function currentClientId(): ?int
    {
        if (!$this->di['auth']->isClientLoggedIn()) {
            return null;
        }

        $clientId = $this->di['session']->get('client_id');

        return is_numeric($clientId) ? (int) $clientId : null;
    }
}
