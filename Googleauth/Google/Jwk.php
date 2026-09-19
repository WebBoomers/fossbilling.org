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

/**
 * Converts an RSA JSON Web Key (RFC 7517) into a PEM public key that OpenSSL
 * can verify with.
 *
 * Google publishes its ID token signing keys as JWKs, and PHP has no built-in
 * JWK reader, so the modulus/exponent pair is wrapped in the DER structure
 * OpenSSL expects (SubjectPublicKeyInfo around an RSAPublicKey).
 */
final class Jwk
{
    /** OID 1.2.840.113549.1.1.1 (rsaEncryption), DER encoded with its NULL parameters. */
    private const string RSA_OID_DER = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

    /**
     * @param array<string, mixed> $jwk
     *
     * @return \OpenSSLAsymmetricKey the parsed public key
     */
    public static function toPublicKey(array $jwk): \OpenSSLAsymmetricKey
    {
        $kty = $jwk['kty'] ?? null;
        if ($kty !== 'RSA') {
            throw new GoogleAuthException(sprintf('Unsupported JWK key type "%s"; only RSA keys are accepted.', is_string($kty) ? $kty : gettype($kty)));
        }

        $modulus = is_string($jwk['n'] ?? null) ? Pkce::base64UrlDecode($jwk['n']) : false;
        $exponent = is_string($jwk['e'] ?? null) ? Pkce::base64UrlDecode($jwk['e']) : false;

        if ($modulus === false || $exponent === false || $modulus === '' || $exponent === '') {
            throw new GoogleAuthException('Malformed RSA JWK: the modulus or exponent could not be decoded.');
        }

        $rsaPublicKey = self::derSequence(
            self::derUnsignedInteger($modulus) . self::derUnsignedInteger($exponent)
        );

        // BIT STRING wrapper: a single leading zero byte means "no unused bits".
        $subjectPublicKeyInfo = self::derSequence(
            self::RSA_OID_DER . self::derTagged("\x03", "\x00" . $rsaPublicKey)
        );

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new GoogleAuthException('OpenSSL rejected the public key rebuilt from the Google JWK.');
        }

        return $key;
    }

    /**
     * Find the signing key for a token header inside a JWKS document.
     *
     * @param array<string, mixed> $jwks
     *
     * @return array<string, mixed>
     */
    public static function findKey(array $jwks, ?string $kid, string $algorithm): array
    {
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys) || $keys === []) {
            throw new GoogleAuthException('The Google JWKS document contained no keys.');
        }

        $candidates = [];
        foreach ($keys as $key) {
            if (!is_array($key)) {
                continue;
            }
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }
            if (isset($key['alg']) && $key['alg'] !== $algorithm) {
                continue;
            }
            $candidates[] = $key;
        }

        if ($kid !== null && $kid !== '') {
            foreach ($candidates as $key) {
                if (($key['kid'] ?? null) === $kid) {
                    return $key;
                }
            }

            throw new GoogleAuthException('No Google signing key matches the key ID in the ID token header.');
        }

        if (count($candidates) === 1) {
            return $candidates[0];
        }

        throw new GoogleAuthException('The ID token header has no key ID and the JWKS document is ambiguous.');
    }

    private static function derUnsignedInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }

        // A leading bit of 1 would make the INTEGER negative, so pad it.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return self::derTagged("\x02", $bytes);
    }

    private static function derSequence(string $contents): string
    {
        return self::derTagged("\x30", $contents);
    }

    private static function derTagged(string $tag, string $contents): string
    {
        return $tag . self::derLength(strlen($contents)) . $contents;
    }

    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
