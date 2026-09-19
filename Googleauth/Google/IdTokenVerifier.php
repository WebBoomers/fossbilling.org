<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Google;

use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\OAuth\Pkce;
use Box\Mod\Googleauth\OAuth\StateToken;

/**
 * Validates the OpenID Connect ID token returned by Google's token endpoint.
 *
 * The token already arrives over a direct, authenticated TLS connection to
 * Google, which OpenID Connect Core 3.1.3.7 considers sufficient on its own.
 * The signature is still verified against Google's published JWKS, because a
 * second independent check costs one cached HTTP request and removes any
 * reliance on the transport being the only thing standing between the extension
 * and a forged identity.
 */
final class IdTokenVerifier
{
    public const string ALGORITHM = 'RS256';

    /** Accepted `iss` values - Google documents both spellings. */
    private const array ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

    /** Clock skew tolerance, in seconds, for `exp` and `iat`. */
    private const int LEEWAY = 120;

    /**
     * @param array<string, mixed> $jwks     the JWKS document fetched from Google
     * @param string               $audience the configured OAuth client ID
     *
     * @return array<string, mixed> the verified claims
     *
     * @throws GoogleAuthException on any failure; the message is for the log only
     */
    public function verify(string $idToken, array $jwks, string $audience, string $expectedNonce, ?int $now = null): array
    {
        $now ??= time();

        [$header, $claims, $signedPayload, $encodedSignature] = $this->decode($idToken);

        // The algorithm is checked before the signature is even decoded, so an
        // `alg: none` token (which carries an empty signature) is rejected for
        // the right reason.
        if (($header['alg'] ?? null) !== self::ALGORITHM) {
            throw new GoogleAuthException(sprintf('ID token signed with unsupported algorithm "%s".', is_string($header['alg'] ?? null) ? $header['alg'] : 'none'));
        }

        $signature = Pkce::base64UrlDecode($encodedSignature);
        if ($signature === false || $signature === '') {
            throw new GoogleAuthException('ID token signature segment could not be decoded.');
        }

        $kid = is_string($header['kid'] ?? null) ? $header['kid'] : null;
        $publicKey = Jwk::toPublicKey(Jwk::findKey($jwks, $kid, self::ALGORITHM));

        $verified = openssl_verify($signedPayload, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            throw new GoogleAuthException('ID token signature verification failed.');
        }

        $this->assertClaims($claims, $audience, $expectedNonce, $now);

        return $claims;
    }

    /**
     * @return array{0: array<string, mixed>, 1: array<string, mixed>, 2: string, 3: string} header, claims, signed payload, encoded signature
     */
    private function decode(string $idToken): array
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new GoogleAuthException('ID token is not a well-formed JWS (expected three dot-separated segments).');
        }

        [$encodedHeader, $encodedClaims, $encodedSignature] = $parts;

        $header = $this->decodeJsonSegment($encodedHeader, 'header');
        $claims = $this->decodeJsonSegment($encodedClaims, 'payload');

        return [$header, $claims, $encodedHeader . '.' . $encodedClaims, $encodedSignature];
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJsonSegment(string $segment, string $label): array
    {
        $json = Pkce::base64UrlDecode($segment);
        if ($json === false) {
            throw new GoogleAuthException(sprintf('ID token %s is not valid base64url.', $label));
        }

        try {
            $decoded = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new GoogleAuthException(sprintf('ID token %s is not valid JSON.', $label), previous: $e);
        }

        if (!is_array($decoded)) {
            throw new GoogleAuthException(sprintf('ID token %s is not a JSON object.', $label));
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function assertClaims(array $claims, string $audience, string $expectedNonce, int $now): void
    {
        $issuer = $claims['iss'] ?? null;
        if (!is_string($issuer) || !in_array($issuer, self::ISSUERS, true)) {
            throw new GoogleAuthException('ID token issuer is not Google.');
        }

        if (!$this->audienceMatches($claims['aud'] ?? null, $audience)) {
            throw new GoogleAuthException('ID token audience does not match the configured OAuth client ID.');
        }

        // When several audiences are present, azp must name this client.
        if (is_array($claims['aud'] ?? null) && count($claims['aud']) > 1) {
            if (($claims['azp'] ?? null) !== $audience) {
                throw new GoogleAuthException('ID token lists multiple audiences and azp does not name this client.');
            }
        }

        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) && !(is_string($exp) && ctype_digit($exp))) {
            throw new GoogleAuthException('ID token has no usable exp claim.');
        }
        if ((int) $exp + self::LEEWAY < $now) {
            throw new GoogleAuthException('ID token has expired.');
        }

        $iat = $claims['iat'] ?? null;
        if (!is_int($iat) && !(is_string($iat) && ctype_digit($iat))) {
            throw new GoogleAuthException('ID token has no usable iat claim.');
        }
        if ((int) $iat - self::LEEWAY > $now) {
            throw new GoogleAuthException('ID token was issued in the future.');
        }

        if (!StateToken::matches($expectedNonce, $claims['nonce'] ?? null)) {
            throw new GoogleAuthException('ID token nonce does not match the value issued for this session.');
        }

        $sub = $claims['sub'] ?? null;
        if (!is_string($sub) || trim($sub) === '') {
            throw new GoogleAuthException('ID token has no sub claim; Google identity cannot be established.');
        }
    }

    private function audienceMatches(mixed $aud, string $expected): bool
    {
        if (is_string($aud)) {
            return hash_equals($expected, $aud);
        }

        if (is_array($aud)) {
            foreach ($aud as $entry) {
                if (is_string($entry) && hash_equals($expected, $entry)) {
                    return true;
                }
            }
        }

        return false;
    }
}
