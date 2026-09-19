<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth;

use Box\Mod\Googleauth\Auth\AccountLinker;
use Box\Mod\Googleauth\Auth\AuthenticationFlow;
use Box\Mod\Googleauth\Auth\CustomerProvisioner;
use Box\Mod\Googleauth\Auth\FlowResult;
use Box\Mod\Googleauth\Auth\PendingSignup;
use Box\Mod\Googleauth\Auth\PendingSignupStore;
use Box\Mod\Googleauth\Auth\SessionAuthenticator;
use Box\Mod\Googleauth\Config\ConfigValidator;
use Box\Mod\Googleauth\Config\ExtensionConfig;
use Box\Mod\Googleauth\Entity\GoogleAccount;
use Box\Mod\Googleauth\Entity\GoogleFlow;
use Box\Mod\Googleauth\Enum\AuthMode;
use Box\Mod\Googleauth\Enum\FlowIntent;
use Box\Mod\Googleauth\Exception\ConfigurationException;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Google\GoogleIdentity;
use Box\Mod\Googleauth\Google\GoogleOAuthClient;
use Box\Mod\Googleauth\Google\IdTokenVerifier;
use Box\Mod\Googleauth\OAuth\Pkce;
use Box\Mod\Googleauth\OAuth\StateToken;
use Box\Mod\Googleauth\Repository\GoogleAccountRepository;
use Box\Mod\Googleauth\Security\FlowState;
use Box\Mod\Googleauth\Security\DoctrineFlowStorage;
use Box\Mod\Googleauth\Security\FlowStateStore;
use Box\Mod\Googleauth\Security\FossBillingSession;
use Box\Mod\Googleauth\Security\ReturnUrlGuard;
use Doctrine\ORM\Tools\SchemaTool;
use FOSSBilling\InformationException;
use FOSSBilling\InjectionAwareInterface;
use FOSSBilling\Interfaces\WidgetProviderInterface;
use Box\Mod\Googleauth\Support\Log;

/**
 * The module service: installation, configuration, widget registration and the
 * entry points for the two halves of the OAuth flow.
 *
 * Developed by Web Boomers - https://www.webboomers.in - support@webboomers.in
 */
class Service implements InjectionAwareInterface, WidgetProviderInterface
{
    public const string MODULE_NAME = 'googleauth';
    public const string CALLBACK_PATH = 'googleauth/callback';

    protected ?\Pimple\Container $di = null;

    /** Guards {@see ensureSchema()} so the tables are verified at most once per request. */
    private static bool $schemaEnsured = false;

    public function setDi(\Pimple\Container $di): void
    {
        $this->di = $di;
    }

    public function getDi(): ?\Pimple\Container
    {
        return $this->di;
    }

    // -----------------------------------------------------------------
    // Module metadata
    // -----------------------------------------------------------------

    /**
     * `manage_settings` is what FOSSBilling checks before letting a staff member
     * open or save this module's settings page, so it has to exist here.
     *
     * @return array<string, mixed>
     */
    public function getModulePermissions(): array
    {
        return [
            'view' => [
                'type' => 'bool',
                'display_name' => __trans('View Google authentication status'),
                'description' => __trans('Allows the staff member to see the Google authentication configuration and connected accounts.'),
            ],
            'purge_links' => [
                'type' => 'bool',
                'display_name' => __trans('Delete Google account connections'),
                'description' => __trans('Allows the staff member to delete every Google account connection. Customer accounts are not affected.'),
            ],
            'manage_settings' => [],
        ];
    }

    /**
     * Template hooks, so the buttons appear without a single core file being
     * touched.
     *
     * @return array<int, array{slot: string, template: string, priority?: int}>
     */
    public function getWidgets(): array
    {
        return [
            [
                'slot' => 'client.page.login.form.after',
                'template' => 'mod_googleauth_login_button',
                'priority' => 20,
            ],
            [
                // The stock signup page has no widget slot inside the form, so
                // the button is rendered at the end of the page and moved into
                // the card by a few lines of progressive enhancement. Without
                // JavaScript it still renders, and still works.
                'slot' => 'client.theme.body.end',
                'template' => 'mod_googleauth_signup_button',
                'priority' => 20,
            ],
            [
                'slot' => 'client.theme.content.before',
                'template' => 'mod_googleauth_profile_card',
                'priority' => 20,
            ],
        ];
    }

    // -----------------------------------------------------------------
    // Installation lifecycle
    // -----------------------------------------------------------------

    public function install(): bool
    {
        $this->assertRequirements();
        $this->createSchema();
        $this->writeDefaultConfiguration();
        $this->connectEventListeners();

        Log::info($this->di, 'Installed the Google Authentication module (disabled, Login Only).');

        return true;
    }

    /**
     * Uninstalling removes the extension, never customer data.
     *
     * The `googleauth_account` table is deliberately left in place: it contains
     * account connections that cannot be reconstructed, and dropping it on an
     * accidental uninstall would silently lock customers out of a sign-in method.
     * Administrators who want a clean removal use "Delete all connections" on the
     * settings page first - see README.md, "Uninstallation".
     */
    public function uninstall(): bool
    {
        Log::info($this->di, 'Uninstalled the Google Authentication module. The googleauth_account table was left in place; use the settings page to delete connections before uninstalling if a clean removal is wanted.');

        return true;
    }

    /**
     * @param array<string, mixed> $manifest
     */
    public function update(array $manifest = []): bool
    {
        $this->assertRequirements();
        $this->createSchema();
        $this->connectEventListeners();
        $this->oauthClient()->forgetCachedMetadata();

        Log::info($this->di, 'Updated the Google Authentication module to version {version}.', [
            'version' => is_scalar($manifest['version'] ?? null) ? (string) $manifest['version'] : 'unknown',
        ]);

        return true;
    }

    /**
     * Fails the install with a readable message instead of a fatal error later
     * on, when the host FOSSBilling is too old or PHP is missing OpenSSL.
     */
    public function assertRequirements(): void
    {
        if (!extension_loaded('openssl')) {
            throw new InformationException('The Google Authentication module requires the PHP "openssl" extension, which is not loaded.');
        }

        if (!interface_exists(WidgetProviderInterface::class)) {
            throw new InformationException('This version of FOSSBilling does not provide the widget system this module needs. FOSSBilling 0.8.2 or newer is required.');
        }

        if (!class_exists(\FOSSBilling\Session::class) || !method_exists(\FOSSBilling\Session::class, 'regenerateId')) {
            throw new InformationException('This version of FOSSBilling does not provide the session API this module needs. FOSSBilling 0.8.2 or newer is required.');
        }

        if (!class_exists(\Box\Mod\Client\Entity\Client::class)) {
            throw new InformationException('This version of FOSSBilling does not provide the Doctrine client entity this module needs. FOSSBilling 0.8.2 or newer is required.');
        }

        // The login button is injected through a widget slot that FOSSBilling
        // only added in 0.8.2. Checking for the slot itself is more honest than
        // comparing version strings, which are placeholders in development and
        // preview builds.
        $this->assertLoginSlotAvailable();
    }

    /**
     * Look for the login form's widget slot in the core template. Missing it is
     * not fatal - everything except the login button still works - so this warns
     * loudly rather than refusing to install.
     */
    private function assertLoginSlotAvailable(): void
    {
        if (!defined('PATH_MODS')) {
            return;
        }

        $template = PATH_MODS . DIRECTORY_SEPARATOR . 'Page' . DIRECTORY_SEPARATOR . 'templates'
            . DIRECTORY_SEPARATOR . 'client' . DIRECTORY_SEPARATOR . 'mod_page_login.html.twig';

        if (!is_readable($template)) {
            return;
        }

        $contents = (string) file_get_contents($template);
        if (str_contains($contents, 'client.page.login.form.after')) {
            return;
        }

        Log::warning($this->di, 
            'The core login template has no "client.page.login.form.after" widget slot, so the Google login button cannot be injected into it. This slot was added in FOSSBilling 0.8.2. Upgrade FOSSBilling, or place the button yourself by overriding mod_page_login.html.twig in your theme (see README.md).'
        );
    }

    /**
     * Make sure this module's tables exist before a flow needs them.
     *
     * An administrator who updates the extension by replacing files, without
     * running the module's Update action, would otherwise hit a "table does not
     * exist" error on the next sign-in. Creating the tables on demand turns that
     * into a non-event. The check runs at most once per request.
     */
    private function ensureSchema(): void
    {
        if (self::$schemaEnsured) {
            return;
        }

        self::$schemaEnsured = true;

        try {
            $this->createSchema();
        } catch (\Throwable $e) {
            Log::error($this->di, 'Could not create the Google Authentication tables on demand: ' . $e->getMessage());
        }
    }

    private function createSchema(): void
    {
        $em = $this->di['em'];

        foreach ([GoogleAccount::class, GoogleFlow::class] as $entity) {
            $metadata = $em->getClassMetadata($entity);
            $tableName = $metadata->getTableName();

            try {
                $schemaManager = $em->getConnection()->createSchemaManager();
                if ($schemaManager->tablesExist([$tableName])) {
                    continue;
                }

                // Only this module's own tables are created, from their current
                // mapping, so the install works the same on MySQL, PostgreSQL and
                // SQLite and never touches anything else in the schema.
                (new SchemaTool($em))->createSchema([$metadata]);
            } catch (\Throwable $e) {
                throw new InformationException('Could not create the :table table: :error', [':table' => $tableName, ':error' => $e->getMessage()]);
            }
        }
    }

    private function writeDefaultConfiguration(): void
    {
        $current = $this->di['mod_config'](self::MODULE_NAME);
        if (is_array($current) && array_key_exists(ExtensionConfig::FIELD_MODE, $current)) {
            return;
        }

        $defaults = ExtensionConfig::defaults()->toArray();
        $defaults['ext'] = ExtensionConfig::EXTENSION_KEY;

        $this->di['mod_service']('extension')->setConfig($defaults);
    }

    /**
     * Register this module's event listeners (see
     * {@see onAfterAdminClientDelete()}) with the hook system.
     */
    private function connectEventListeners(): void
    {
        try {
            $this->di['mod_service']('hook')->batchConnect(self::MODULE_NAME);
        } catch (\Throwable $e) {
            Log::warning($this->di, 'Could not register the Google Authentication event listeners: ' . $e->getMessage());
        }
    }

    /**
     * Housekeeping: when an administrator deletes a customer, the orphaned
     * connection goes with it. Nothing else is touched.
     */
    public static function onAfterAdminClientDelete(\Box_Event $event): void
    {
        $di = $event->getDi();
        $params = $event->getParameters();
        $clientId = (int) ($params['id'] ?? 0);

        if ($clientId <= 0) {
            return;
        }

        try {
            /** @var GoogleAccountRepository $repository */
            $repository = $di['em']->getRepository(GoogleAccount::class);
            $removed = $repository->deleteByClientId($clientId);

            if ($removed > 0) {
                Log::info($di, 'Removed the Google account connection of deleted client #{client_id}.', ['client_id' => $clientId]);
            }
        } catch (\Throwable $e) {
            Log::warning($di, 'Could not clean up the Google account connection of client #{client_id}: {error}', [
                'client_id' => $clientId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    // -----------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------

    public function getConfig(): ExtensionConfig
    {
        return ExtensionConfig::fromArray($this->di['mod_config'](self::MODULE_NAME));
    }

    /**
     * Validate and persist administrator settings.
     *
     * Storage goes through the core extension service, which encrypts the whole
     * configuration blob before it reaches the database, so the client secret is
     * never at rest in plain text.
     *
     * @param array<string, mixed> $input
     */
    public function saveConfig(array $input): bool
    {
        $existing = $this->getConfig();

        try {
            $validated = (new ConfigValidator())->validate($input, $existing->clientSecret);
        } catch (ConfigurationException $e) {
            Log::warning($this->di, $e->getMessage());

            throw new InformationException($e->getUserMessage());
        }

        $validated['ext'] = ExtensionConfig::EXTENSION_KEY;
        $this->di['mod_service']('extension')->setConfig($validated);

        $this->oauthClient()->forgetCachedMetadata();

        Log::info($this->di, 'Google authentication settings updated (enabled: {enabled}, mode: {mode}).', [
            'enabled' => $validated[ExtensionConfig::FIELD_ENABLED] ? 'yes' : 'no',
            'mode' => $validated[ExtensionConfig::FIELD_MODE],
        ]);

        return true;
    }

    /**
     * The exact value that must be added to the Google Cloud Console.
     *
     * Derived from this installation's configured system URL, so the extension
     * works on any domain without a single hard-coded host.
     */
    public function getRedirectUri(): string
    {
        return $this->di['url']->link(self::CALLBACK_PATH);
    }

    /**
     * Everything the settings page shows about the current state.
     *
     * @return array<string, mixed>
     */
    public function getStatus(): array
    {
        $config = $this->getConfig();

        $status = $config->toSafeArray();
        $status['redirect_uri'] = $this->getRedirectUri();
        $status['modes'] = AuthMode::options();
        $status['linked_accounts'] = 0;
        $status['scopes'] = GoogleOAuthClient::SCOPES;
        $status['table_ready'] = false;
        $status['flow_table_ready'] = false;

        try {
            $status['linked_accounts'] = $this->accountRepository()->countLinks();
            $status['table_ready'] = true;

            $status['flow_table_ready'] = $this->di['em']
                ->getConnection()
                ->createSchemaManager()
                ->tablesExist([$this->di['em']->getClassMetadata(GoogleFlow::class)->getTableName()]);
        } catch (\Throwable $e) {
            Log::warning($this->di, 'Could not read the Google account connections table: ' . $e->getMessage());
        }

        if (!$config->enabled) {
            $status['state'] = 'disabled';
        } elseif (!$config->isConfigured()) {
            $status['state'] = 'incomplete';
        } else {
            $status['state'] = 'ready';
        }

        return $status;
    }

    /**
     * Delete every Google account connection. Customers, invoices, orders and
     * tickets are untouched; only the ability to sign in with Google is removed.
     */
    public function purgeAllLinks(): int
    {
        $removed = $this->accountRepository()->deleteAll();
        Log::info($this->di, 'Deleted {count} Google account connection(s). No customer accounts were affected.', ['count' => $removed]);

        return $removed;
    }

    // -----------------------------------------------------------------
    // Customer-facing helpers
    // -----------------------------------------------------------------

    /**
     * Context for the login/signup button widgets. Safe for guests: it contains
     * no credentials.
     *
     * @return array<string, mixed>
     */
    public function getButtonContext(): array
    {
        $config = $this->getConfig();
        $operational = $config->isOperational();

        return [
            'enabled' => $operational,
            'mode' => $config->mode->value,
            'show_on_login' => $operational && $config->mode->allowsLogin(),
            'show_on_signup' => $operational && $config->mode->allowsSignup(),
            'login_url' => $this->di['url']->link('googleauth/login'),
            'signup_url' => $this->di['url']->link('googleauth/signup'),
        ];
    }

    /**
     * Connection state for the signed-in customer's profile screen.
     *
     * @return array<string, mixed>
     */
    public function getClientLinkStatus(int $clientId): array
    {
        $config = $this->getConfig();

        // This method is called from the client profile widget. A widget must
        // never take the whole profile page down because an extension table is
        // missing (for example after a file-only module replacement).
        if (!$config->isOperational()) {
            return [
                'available' => false,
                'connected' => false,
                'google_email' => null,
                'connected_at' => null,
                'last_login_at' => null,
                'can_disconnect' => false,
                'connect_url' => null,
            ];
        }

        try {
            // Ensure the Doctrine tables exist even when the module was updated
            // by replacing files instead of running its Update action.
            $this->ensureSchema();
            $link = $this->accountLinker()->findByClientId($clientId);

            return [
                'available' => true,
                'connected' => $link instanceof GoogleAccount,
                'google_email' => $link?->getGoogleEmail(),
                'connected_at' => $link?->getCreatedAt()->format('Y-m-d H:i:s'),
                'last_login_at' => $link?->getLastLoginAt()?->format('Y-m-d H:i:s'),
                'can_disconnect' => $link instanceof GoogleAccount && $this->clientHasAlternativeLogin($clientId),
                'connect_url' => $this->di['url']->link('googleauth/link', ['CSRFToken' => $this->csrfToken()]),
            ];
        } catch (\Throwable $e) {
            // Never break the customer's profile page because GoogleAuth has a
            // database/configuration problem. Log the diagnostic server-side
            // and hide the optional card until the module is repaired.
            Log::error($this->di, 'GoogleAuth profile widget could not load client status: ' . $e->getMessage());

            return [
                'available' => false,
                'connected' => false,
                'google_email' => null,
                'connected_at' => null,
                'last_login_at' => null,
                'can_disconnect' => false,
                'connect_url' => null,
            ];
        }
    }

    /**
     * Lock-out protection: a customer may only disconnect Google while another
     * way in still exists.
     *
     * Every FOSSBilling customer has a password hash (one is generated even for
     * Google signups) and can always recover access with "Forgot password",
     * provided their email address is usable. The check is therefore that the
     * account has a usable password hash and an email address.
     */
    public function clientHasAlternativeLogin(int $clientId): bool
    {
        $client = $this->di['em']->getRepository(\Box\Mod\Client\Entity\Client::class)->find($clientId);

        if (!$client instanceof \Box\Mod\Client\Entity\Client) {
            return false;
        }

        $hash = (string) $client->getPass();
        $email = (string) $client->getEmail();

        return $hash !== '' && $email !== '';
    }

    public function disconnect(int $clientId): bool
    {
        if (!$this->clientHasAlternativeLogin($clientId)) {
            throw new InformationException('Set a password on your account before disconnecting Google, so that you do not lose access.');
        }

        return $this->accountLinker()->unlink($clientId);
    }

    // -----------------------------------------------------------------
    // OAuth flow
    // -----------------------------------------------------------------

    /**
     * Start a flow: create the PKCE pair, the state and the nonce, remember them
     * server-side and return the Google URL to redirect the browser to.
     */
    public function createAuthorizationUrl(FlowIntent $intent, mixed $returnTo = null): string
    {
        $config = $this->getConfig();
        $config->assertOperational();

        $this->assertIntentAllowed($config, $intent);
        $this->throttleFlowStart();
        $this->ensureSchema();

        $clientId = null;
        if ($intent === FlowIntent::Link) {
            $clientId = $this->requireLoggedInClientId();
        }

        $pkce = Pkce::create();

        // The correlation token binds this flow to this browser. It travels in
        // our own SameSite=Lax cookie rather than the session, because
        // FOSSBilling marks the session cookie SameSite=Strict by default and
        // browsers withhold Strict cookies on the return navigation from Google.
        $correlation = StateToken::generate();

        $state = new FlowState(
            StateToken::generate(),
            hash('sha256', $correlation),
            StateToken::generate(),
            $pkce->verifier,
            $intent,
            ReturnUrlGuard::sanitize($returnTo, $this->defaultReturnPath($intent)),
            time(),
            $clientId,
        );

        $this->flowStateStore()->store($state);
        $this->issueCorrelationCookie($correlation);

        return $this->oauthClient()->buildAuthorizationUrl(
            $config,
            $this->getRedirectUri(),
            $state->state,
            $state->nonce,
            $pkce->challenge,
        );
    }

    /**
     * Finish a flow. Returns where to send the visitor and what to tell them.
     *
     * @param array<string, mixed> $query the callback query parameters
     */
    public function handleCallback(array $query): FlowResult
    {
        $config = $this->getConfig();
        $config->assertOperational();

        $this->throttleFlowStart();
        $this->ensureSchema();

        // Google reports a refusal here; there is no code to exchange.
        $error = $query['error'] ?? null;
        if (is_string($error) && $error !== '') {
            $this->flowStateStore()->discard($query['state'] ?? null);
            $this->clearCorrelationCookie();
            Log::info($this->di, 'Google returned an authorization error: {error}', ['error' => $error]);

            return FlowResult::info(
                AuthenticationFlow::LOGIN_PATH,
                $error === 'access_denied'
                    ? 'Google sign-in was cancelled. You can try again or sign in with your usual details.'
                    : 'Google authentication could not be completed. Please try again or use your usual login details.',
            );
        }

        $correlation = $this->di['request']->cookies->get(FlowStateStore::COOKIE_NAME);
        $this->clearCorrelationCookie();

        $state = $this->flowStateStore()->consume($query['state'] ?? null, $correlation);

        $code = $query['code'] ?? null;
        if (!is_string($code) || $code === '') {
            throw new GoogleAuthException('Google callback contained no authorization code.');
        }

        $tokens = $this->oauthClient()->exchangeAuthorizationCode(
            $config,
            $code,
            $this->getRedirectUri(),
            $state->codeVerifier,
        );

        $claims = (new IdTokenVerifier())->verify(
            (string) $tokens['id_token'],
            $this->oauthClient()->jwks(),
            $config->clientId,
            $state->nonce,
        );

        $identity = GoogleIdentity::fromClaims($claims);

        return $this->authenticationFlow($config)->handle($state, $identity);
    }

    public function peekPendingSignup(): ?PendingSignup
    {
        return $this->pendingSignupStore()->peek();
    }

    /**
     * Finish a signup that needed extra profile fields.
     *
     * @param array<string, mixed> $fields
     */
    public function completePendingSignup(array $fields): FlowResult
    {
        $config = $this->getConfig();
        $config->assertOperational();

        $pending = $this->pendingSignupStore()->consume();
        if (!$pending instanceof PendingSignup) {
            throw new GoogleAuthException(
                'Signup completion attempted with no pending Google identity in the session.',
                'This sign-up has expired. Please start again.',
            );
        }

        return $this->authenticationFlow($config)->completeSignup($pending, $fields);
    }

    public function clearPendingSignup(): void
    {
        $this->pendingSignupStore()->clear();
    }

    /**
     * @return list<array{name: string, required: bool, custom: bool, title: string}>
     */
    public function getPendingSignupFields(PendingSignup $pending): array
    {
        $provisioner = new CustomerProvisioner($this->di);
        $missing = $provisioner->missingRequiredFields($pending->identity);
        $customFields = (array) ($this->di['mod_config']('client')['custom_fields'] ?? []);

        $fields = [];
        foreach ($missing as $name) {
            $isCustom = array_key_exists($name, $customFields);
            $title = $isCustom && !empty($customFields[$name]['title'])
                ? (string) $customFields[$name]['title']
                : ucwords(str_replace('_', ' ', $name));

            $fields[] = [
                'name' => $name,
                'required' => true,
                'custom' => $isCustom,
                'title' => $title,
            ];
        }

        return $fields;
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    private function assertIntentAllowed(ExtensionConfig $config, FlowIntent $intent): void
    {
        $allowed = match ($intent) {
            FlowIntent::Login => $config->mode->allowsLogin(),
            FlowIntent::Signup => $config->mode->allowsSignup(),
            // Connecting Google to an account you are already signed in to is
            // what makes Login Only usable, so it is allowed in every mode.
            FlowIntent::Link => true,
        };

        if (!$allowed) {
            throw new GoogleAuthException(
                sprintf('Flow intent "%s" is not permitted in authentication mode "%s".', $intent->value, $config->mode->value),
                'That Google sign-in option is not available on this site.',
            );
        }
    }

    private function requireLoggedInClientId(): int
    {
        if (!$this->di['auth']->isClientLoggedIn()) {
            throw new GoogleAuthException(
                'Refused to start a Google account linking flow for a visitor who is not signed in.',
                'Please sign in before connecting your Google account.',
            );
        }

        $clientId = $this->di['session']->get('client_id');
        if (!is_numeric($clientId)) {
            throw new GoogleAuthException('Refused to start a Google account linking flow: no customer in the session.');
        }

        return (int) $clientId;
    }

    private function defaultReturnPath(FlowIntent $intent): string
    {
        return $intent === FlowIntent::Link ? AuthenticationFlow::PROFILE_PATH : '/';
    }

    /**
     * Reuse FOSSBilling's own guest quota for the OAuth endpoints, so this route
     * cannot be used to bypass the rate limiting that protects the rest of the
     * guest surface.
     */
    private function throttleFlowStart(): void
    {
        try {
            $result = $this->di['rate_limiter']->consume('api_guest', (string) $this->di['request']->getClientIp());
        } catch (\Throwable $e) {
            Log::warning($this->di, 'Rate limiting unavailable for the Google authentication endpoints: ' . $e->getMessage());

            return;
        }

        if ($result->isLimited()) {
            throw new GoogleAuthException(
                'Google authentication endpoint blocked by the api_guest rate limit.',
                'Too many attempts. Please wait a little while and try again.',
            );
        }
    }

    private function csrfToken(): string
    {
        $token = $this->di['session']->get('csrf_token');

        return is_string($token) ? $token : '';
    }

    /**
     * Validate a CSRF token against the one in the session, for the two
     * browser-initiated GET/guest endpoints that FOSSBilling's API layer does
     * not cover on its own. The token itself is core's.
     */
    public function assertCsrfToken(mixed $provided): void
    {
        $expected = $this->csrfToken();

        if ($expected === '' || !is_string($provided) || $provided === '' || !hash_equals($expected, $provided)) {
            throw new GoogleAuthException(
                'Rejected a Google authentication request with a missing or invalid CSRF token.',
                'That request could not be verified. Please try again from your account page.',
            );
        }
    }

    private function accountRepository(): GoogleAccountRepository
    {
        /** @var GoogleAccountRepository $repository */
        $repository = $this->di['em']->getRepository(GoogleAccount::class);

        return $repository;
    }

    public function accountLinker(): AccountLinker
    {
        return new AccountLinker($this->di);
    }

    private function oauthClient(): GoogleOAuthClient
    {
        $cache = null;
        if (isset($this->di['cache']) && $this->di['cache'] instanceof \Psr\Cache\CacheItemPoolInterface) {
            $cache = $this->di['cache'];
        }

        return new GoogleOAuthClient($this->di['http_client'], $cache);
    }

    /**
     * Issue the browser-binding cookie for a flow.
     *
     * SameSite=Lax is the point of the whole exercise: Lax cookies *are* sent on
     * a top-level GET navigation, which is exactly what Google's redirect back
     * to the callback is. HttpOnly keeps it away from scripts, and it is marked
     * Secure whenever the request is HTTPS.
     */
    private function issueCorrelationCookie(string $correlation): void
    {
        try {
            $this->di['cookie_queue']->queue(
                FlowStateStore::COOKIE_NAME,
                $correlation,
                time() + FlowStateStore::LIFETIME_SECONDS,
                '/',
                null,
                (bool) $this->di['request']->isSecure(),
                true,
                'Lax',
            );
        } catch (\Throwable $e) {
            Log::warning($this->di, 'Could not set the Google sign-in correlation cookie: ' . $e->getMessage());
        }
    }

    private function clearCorrelationCookie(): void
    {
        try {
            $this->di['cookie_queue']->queue(
                FlowStateStore::COOKIE_NAME,
                '',
                time() - 3600,
                '/',
                null,
                (bool) $this->di['request']->isSecure(),
                true,
                'Lax',
            );
        } catch (\Throwable $e) {
            Log::debug($this->di, 'Could not clear the Google sign-in correlation cookie: ' . $e->getMessage());
        }
    }

    private function flowStateStore(): FlowStateStore
    {
        return new FlowStateStore(new DoctrineFlowStorage($this->di));
    }

    private function pendingSignupStore(): PendingSignupStore
    {
        return new PendingSignupStore(new FossBillingSession($this->di['session']));
    }

    private function authenticationFlow(ExtensionConfig $config): AuthenticationFlow
    {
        return new AuthenticationFlow(
            $this->di,
            $config,
            $this->accountLinker(),
            new CustomerProvisioner($this->di),
            new SessionAuthenticator($this->di),
            $this->pendingSignupStore(),
        );
    }
}
