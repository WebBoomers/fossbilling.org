<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Google;

use Box\Mod\Googleauth\Config\ExtensionConfig;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\OAuth\Pkce;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * All outbound traffic to Google: discovery, the authorization URL, the token
 * exchange and the signing keys.
 *
 * Nothing in here ever writes a credential or a token to the log. Failures are
 * raised as {@see GoogleAuthException} with a technical message for the log and
 * a neutral sentence for the visitor.
 */
final class GoogleOAuthClient
{
    /** Minimum scopes needed to identify the customer. Nothing else is requested. */
    public const array SCOPES = ['openid', 'email', 'profile'];

    private const string DISCOVERY_CACHE_KEY = 'googleauth_discovery';
    private const string JWKS_CACHE_KEY = 'googleauth_jwks';
    private const int DISCOVERY_TTL = 86400;
    private const int JWKS_TTL = 3600;
    private const int HTTP_TIMEOUT = 10;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly ?CacheItemPoolInterface $cache = null,
    ) {
    }

    public function endpoints(): GoogleEndpoints
    {
        $document = $this->cached(self::DISCOVERY_CACHE_KEY, self::DISCOVERY_TTL, function (): array {
            return $this->getJson(GoogleEndpoints::DISCOVERY_URL);
        });

        if ($document === null) {
            // Discovery is a convenience, not a dependency.
            return new GoogleEndpoints();
        }

        return GoogleEndpoints::fromDiscoveryDocument($document);
    }

    /**
     * Build the URL the visitor's browser is sent to.
     *
     * `prompt=select_account` is used so a shared browser does not silently
     * re-use whichever Google account happens to be signed in.
     */
    public function buildAuthorizationUrl(
        ExtensionConfig $config,
        string $redirectUri,
        string $state,
        string $nonce,
        string $codeChallenge,
    ): string {
        $parameters = [
            'client_id' => $config->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', self::SCOPES),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => Pkce::METHOD,
            'access_type' => 'online',
            'include_granted_scopes' => 'false',
            'prompt' => 'select_account',
        ];

        return $this->endpoints()->authorizationEndpoint . '?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchange the authorization code for tokens.
     *
     * @return array<string, mixed> the raw token response
     */
    public function exchangeAuthorizationCode(
        ExtensionConfig $config,
        string $code,
        string $redirectUri,
        string $codeVerifier,
    ): array {
        $endpoint = $this->endpoints()->tokenEndpoint;

        try {
            $response = $this->httpClient->request('POST', $endpoint, [
                'timeout' => self::HTTP_TIMEOUT,
                'headers' => ['Accept' => 'application/json'],
                'body' => [
                    'code' => $code,
                    'client_id' => $config->clientId,
                    'client_secret' => $config->clientSecret,
                    'redirect_uri' => $redirectUri,
                    'grant_type' => 'authorization_code',
                    'code_verifier' => $codeVerifier,
                ],
            ]);

            $status = $response->getStatusCode();
            $payload = $response->toArray(false);
        } catch (\Throwable $e) {
            throw new GoogleAuthException(
                'Token exchange with Google failed: ' . $e->getMessage(),
                'Google could not be reached right now. Please try again in a moment, or sign in with your usual details.',
                previous: $e,
            );
        }

        if ($status !== 200) {
            // Google returns a machine-readable error code here. It is safe to
            // log (it never contains the secret or the code) and useful to
            // administrators diagnosing a misconfiguration.
            $error = is_string($payload['error'] ?? null) ? $payload['error'] : 'unknown_error';
            $description = is_string($payload['error_description'] ?? null) ? $payload['error_description'] : '';

            throw new GoogleAuthException(
                sprintf('Google rejected the token exchange (HTTP %d, error "%s"%s).', $status, $error, $description === '' ? '' : ': ' . $description),
                $this->userMessageForTokenError($error),
            );
        }

        if (!is_string($payload['id_token'] ?? null) || $payload['id_token'] === '') {
            throw new GoogleAuthException('Google token response contained no ID token.');
        }

        return $payload;
    }

    /**
     * @return array<string, mixed> the JWKS document
     */
    public function jwks(): array
    {
        $jwksUri = $this->endpoints()->jwksUri;

        $document = $this->cached(self::JWKS_CACHE_KEY, self::JWKS_TTL, function () use ($jwksUri): array {
            return $this->getJson($jwksUri);
        });

        if ($document === null || !is_array($document['keys'] ?? null)) {
            throw new GoogleAuthException(
                'Google signing keys (JWKS) could not be retrieved.',
                'Google could not be reached right now. Please try again in a moment, or sign in with your usual details.',
            );
        }

        return $document;
    }

    /**
     * Drop the cached discovery and JWKS documents (used after a configuration
     * change and by the "test connection" action in the admin settings).
     */
    public function forgetCachedMetadata(): void
    {
        if ($this->cache === null) {
            return;
        }

        try {
            $this->cache->deleteItem(self::DISCOVERY_CACHE_KEY);
            $this->cache->deleteItem(self::JWKS_CACHE_KEY);
        } catch (\Throwable) {
            // A cache that refuses to forget is not worth failing a request over.
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function getJson(string $url): array
    {
        $response = $this->httpClient->request('GET', $url, [
            'timeout' => self::HTTP_TIMEOUT,
            'headers' => ['Accept' => 'application/json'],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new GoogleAuthException(sprintf('Unexpected HTTP %d from %s.', $response->getStatusCode(), $url));
        }

        return $response->toArray();
    }

    /**
     * @param callable():array<string, mixed> $factory
     *
     * @return array<string, mixed>|null null when the document could not be produced
     */
    private function cached(string $key, int $ttl, callable $factory): ?array
    {
        if ($this->cache === null) {
            try {
                return $factory();
            } catch (\Throwable) {
                return null;
            }
        }

        try {
            $item = $this->cache->getItem($key);
            if ($item->isHit()) {
                $value = $item->get();
                if (is_array($value)) {
                    return $value;
                }
            }

            $value = $factory();
            $item->set($value);
            $item->expiresAfter($ttl);
            $this->cache->save($item);

            return $value;
        } catch (\Throwable) {
            return null;
        }
    }

    private function userMessageForTokenError(string $error): string
    {
        return match ($error) {
            'invalid_grant' => 'This Google sign-in link has expired or was already used. Please start again.',
            'invalid_client', 'unauthorized_client' => 'Google sign-in is not configured correctly on this site. Please contact support.',
            'redirect_uri_mismatch' => 'Google sign-in is not configured correctly on this site. Please contact support.',
            default => 'Google authentication could not be completed. Please try again or use your usual login details.',
        };
    }
}
