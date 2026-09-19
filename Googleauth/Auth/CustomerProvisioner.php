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
use Box\Mod\Googleauth\Google\GoogleIdentity;
use Box\Mod\Googleauth\Support\Log;

/**
 * Creates FOSSBilling customers from a verified Google identity.
 *
 * Everything goes through the core client service
 * (`Box\Mod\Client\Service::guestCreateClient()`), so group defaults, currency,
 * validation, the signup events and the welcome email all behave exactly as they
 * do for a form signup. The extension never writes to the customer table itself.
 *
 * Passwords: no password is passed in, which makes the core service generate a
 * 32-character cryptographically random one and store it hashed. It is never
 * derived from the Google identity, never displayed and never emailed. A
 * customer who later wants to sign in without Google uses the normal "forgot
 * password" flow.
 */
final class CustomerProvisioner
{
    /**
     * Fields the core signup form can require that a Google identity can supply
     * on its own. Anything else has to be asked for.
     */
    private const array SATISFIED_BY_GOOGLE = ['email', 'first_name'];

    /**
     * Fields the completion step is allowed to accept. Mirrors the allowlist the
     * core guest signup uses, minus the credentials.
     */
    private const array ACCEPTED_EXTRA_FIELDS = [
        'last_name', 'phone', 'phone_cc', 'gender', 'birthday',
        'company', 'company_vat', 'company_number', 'type',
        'address_1', 'address_2', 'city', 'state', 'postcode', 'country',
        'lang', 'timezone',
        'custom_1', 'custom_2', 'custom_3', 'custom_4', 'custom_5',
        'custom_6', 'custom_7', 'custom_8', 'custom_9', 'custom_10',
        'custom_11', 'custom_12', 'custom_13', 'custom_14', 'custom_15',
        'custom_16', 'custom_17', 'custom_18', 'custom_19', 'custom_20',
    ];

    public function __construct(private readonly \Pimple\Container $di)
    {
    }

    /**
     * Honours the core "New registrations are temporarily disabled" switch:
     * Google must never be a way around it.
     */
    public function signupAllowed(): bool
    {
        $config = $this->di['mod_config']('client');

        return empty($config['disable_signup']);
    }

    public function emailAlreadyRegistered(string $email): bool
    {
        return (bool) $this->di['mod_service']('client')->clientAlreadyExists(strtolower(trim($email)));
    }

    /**
     * Which extra fields this installation requires that Google cannot provide.
     *
     * @param array<string, mixed> $collected values already gathered from the completion form
     *
     * @return list<string>
     */
    public function missingRequiredFields(GoogleIdentity $identity, array $collected = []): array
    {
        $available = $this->buildData($identity, $collected);
        $config = $this->di['mod_config']('client');

        $missing = [];

        foreach ((array) ($config['required'] ?? []) as $field) {
            if (!is_string($field) || in_array($field, self::SATISFIED_BY_GOOGLE, true)) {
                continue;
            }

            if (empty($available[$field])) {
                $missing[] = $field;
            }
        }

        foreach ((array) ($config['custom_fields'] ?? []) as $name => $definition) {
            if (!is_string($name) || !is_array($definition)) {
                continue;
            }

            $active = !empty($definition['active']);
            $required = !empty($definition['required']);

            if ($active && $required && empty($available[$name])) {
                $missing[] = $name;
            }
        }

        return array_values(array_unique($missing));
    }

    /**
     * @param array<string, mixed> $collected
     */
    public function create(GoogleIdentity $identity, array $collected = []): Client
    {
        $identity->assertEmailVerified();

        if (!$this->signupAllowed()) {
            throw new GoogleAuthException(
                'Google signup refused: new registrations are disabled in the client module settings.',
                'New registrations are temporarily disabled on this site.',
            );
        }

        $this->consumeSignupRateLimits($identity->email);

        $data = $this->buildData($identity, $collected);

        $clientService = $this->di['mod_service']('client');

        // Reuse the core validators so a Google signup is held to exactly the
        // same completeness rules as a form signup.
        $clientService->checkExtraRequiredFields($data);
        $clientService->checkCustomFields($data);

        try {
            $client = $clientService->guestCreateClient($data);
        } catch (\Throwable $e) {
            throw new GoogleAuthException(
                'Creating a customer from a Google identity failed: ' . $e->getMessage(),
                'Your account could not be created right now. Please try again or contact support.',
                previous: $e,
            );
        }

        if (!$client instanceof Client) {
            throw new GoogleAuthException('The client service did not return a customer for a Google signup.');
        }

        $this->markAsGoogleAccount($client, $identity);

        return $client;
    }

    /**
     * Record how the account was created, and accept Google's verification of
     * the address so the customer is not asked to confirm an email address they
     * have just proved they control.
     */
    private function markAsGoogleAccount(Client $client, GoogleIdentity $identity): void
    {
        try {
            $client->setAuthType('google');
            if ($identity->emailVerified) {
                $client->setEmailApproved(true);
            }
            $this->di['em']->flush();
        } catch (\Throwable $e) {
            Log::warning($this->di, 'Could not flag client #{client_id} as a Google account: {error}', [
                'client_id' => $client->getId(),
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * @param array<string, mixed> $collected
     *
     * @return array<string, mixed>
     */
    public function buildData(GoogleIdentity $identity, array $collected = []): array
    {
        $data = [
            'email' => $identity->email,
            'first_name' => $identity->firstName(),
        ];

        $lastName = $identity->lastName();
        if ($lastName !== null) {
            $data['last_name'] = $lastName;
        }

        foreach (self::ACCEPTED_EXTRA_FIELDS as $field) {
            if (!array_key_exists($field, $collected)) {
                continue;
            }

            $value = $collected[$field];
            if (is_string($value)) {
                $value = trim($value);
            }

            if ($value === '' || $value === null) {
                continue;
            }

            if (!is_scalar($value)) {
                continue;
            }

            $data[$field] = $value;
        }

        return $data;
    }

    /**
     * Google signups consume the same signup quotas as form signups, so this
     * route cannot be used to sidestep the abuse controls.
     */
    private function consumeSignupRateLimits(string $email): void
    {
        $ip = (string) $this->di['request']->getClientIp();

        try {
            $this->di['rate_limiter']->consumeOrThrow('client_signup', $ip);
            $emailLimit = $this->di['rate_limiter']->consume('client_signup_email', strtolower($email));
        } catch (\FOSSBilling\Security\RateLimitException $e) {
            throw new GoogleAuthException(
                'Google signup blocked by the client_signup rate limit.',
                'Too many sign-up attempts. Please wait a little while and try again.',
                previous: $e,
            );
        } catch (\Throwable $e) {
            // A rate limiter that is misconfigured must not become an open door,
            // but it must also not break sign-ups; log and continue.
            Log::warning($this->di, 'Signup rate limiting unavailable: ' . $e->getMessage());

            return;
        }

        if ($emailLimit->isLimited()) {
            throw new GoogleAuthException(
                'Google signup blocked by the client_signup_email rate limit.',
                'Too many sign-up attempts. Please wait a little while and try again.',
            );
        }
    }
}
