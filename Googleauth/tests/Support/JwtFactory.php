<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Support;

use Box\Mod\Googleauth\OAuth\Pkce;

/**
 * Mints RS256 ID tokens with a throwaway key pair, so the verifier can be tested
 * against real signatures instead of a stubbed-out check.
 */
final class JwtFactory
{
    private \OpenSSLAsymmetricKey $privateKey;

    /** @var array<string, mixed> */
    private array $jwk;

    public function __construct(private readonly string $kid = 'test-key')
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            throw new \RuntimeException('Could not generate a test RSA key pair.');
        }

        $this->privateKey = $resource;

        $details = openssl_pkey_get_details($resource);
        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('Could not read the generated test key.');
        }

        $this->jwk = [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->kid,
            'n' => Pkce::base64UrlEncode($details['rsa']['n']),
            'e' => Pkce::base64UrlEncode($details['rsa']['e']),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jwks(): array
    {
        return ['keys' => [$this->jwk]];
    }

    /**
     * @return array<string, mixed>
     */
    public function jwk(): array
    {
        return $this->jwk;
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headerOverrides
     */
    public function sign(array $claims, array $headerOverrides = []): string
    {
        $header = array_merge(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $this->kid], $headerOverrides);

        $segments = Pkce::base64UrlEncode((string) json_encode($header))
            . '.' . Pkce::base64UrlEncode((string) json_encode($claims));

        $signature = '';
        openssl_sign($segments, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        return $segments . '.' . Pkce::base64UrlEncode($signature);
    }

    /**
     * An otherwise valid token whose signature belongs to different content.
     *
     * @param array<string, mixed> $claims
     */
    public function signThenTamper(array $claims): string
    {
        $token = $this->sign($claims);
        [$header, , $signature] = explode('.', $token);

        $tampered = $claims;
        $tampered['sub'] = 'attacker-subject';

        return $header . '.' . Pkce::base64UrlEncode((string) json_encode($tampered)) . '.' . $signature;
    }
}
