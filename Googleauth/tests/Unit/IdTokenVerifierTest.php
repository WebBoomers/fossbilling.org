<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Google\IdTokenVerifier;
use Box\Mod\Googleauth\OAuth\Pkce;
use Box\Mod\Googleauth\OAuth\StateToken;
use Box\Mod\Googleauth\Tests\Support\JwtFactory;
use PHPUnit\Framework\TestCase;

final class IdTokenVerifierTest extends TestCase
{
    private const string AUDIENCE = '1234567890-abc.apps.googleusercontent.com';

    private JwtFactory $factory;
    private IdTokenVerifier $verifier;
    private string $nonce;
    private int $now;

    protected function setUp(): void
    {
        $this->factory = new JwtFactory();
        $this->verifier = new IdTokenVerifier();
        $this->nonce = StateToken::generate();
        $this->now = 1_800_000_000;
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => 'https://accounts.google.com',
            'aud' => self::AUDIENCE,
            'sub' => '110248495921238986420',
            'email' => 'customer@example.com',
            'email_verified' => true,
            'nonce' => $this->nonce,
            'iat' => $this->now - 30,
            'exp' => $this->now + 3600,
        ], $overrides);
    }

    private function verify(string $token, ?string $audience = null, ?string $nonce = null): array
    {
        return $this->verifier->verify(
            $token,
            $this->factory->jwks(),
            $audience ?? self::AUDIENCE,
            $nonce ?? $this->nonce,
            $this->now
        );
    }

    public function testAGenuineTokenIsAccepted(): void
    {
        $claims = $this->verify($this->factory->sign($this->claims()));

        self::assertSame('110248495921238986420', $claims['sub']);
        self::assertSame('customer@example.com', $claims['email']);
    }

    public function testTheAlternativeIssuerSpellingIsAccepted(): void
    {
        $claims = $this->verify($this->factory->sign($this->claims(['iss' => 'accounts.google.com'])));

        self::assertSame('accounts.google.com', $claims['iss']);
    }

    public function testATokenFromAnotherIssuerIsRejected(): void
    {
        $this->expectExceptionMessageMatches('/issuer/i');
        $this->verify($this->factory->sign($this->claims(['iss' => 'https://accounts.evil.example'])));
    }

    public function testATokenMintedForAnotherClientIsRejected(): void
    {
        $this->expectExceptionMessageMatches('/audience/i');
        $this->verify($this->factory->sign($this->claims(['aud' => 'someone-else.apps.googleusercontent.com'])));
    }

    public function testMultipleAudiencesRequireAMatchingAzp(): void
    {
        $token = $this->factory->sign($this->claims([
            'aud' => [self::AUDIENCE, 'other.apps.googleusercontent.com'],
            'azp' => 'other.apps.googleusercontent.com',
        ]));

        $this->expectExceptionMessageMatches('/azp/i');
        $this->verify($token);
    }

    public function testAReplayedTokenFromAnotherSessionIsRejected(): void
    {
        // Correct signature, correct audience - but minted for a different
        // authorization request, so the nonce does not match this session.
        $token = $this->factory->sign($this->claims(['nonce' => StateToken::generate()]));

        $this->expectExceptionMessageMatches('/nonce/i');
        $this->verify($token);
    }

    public function testATokenWithNoNonceIsRejected(): void
    {
        $claims = $this->claims();
        unset($claims['nonce']);

        $this->expectExceptionMessageMatches('/nonce/i');
        $this->verify($this->factory->sign($claims));
    }

    public function testAnExpiredTokenIsRejected(): void
    {
        $this->expectExceptionMessageMatches('/expired/i');
        $this->verify($this->factory->sign($this->claims(['exp' => $this->now - 600])));
    }

    public function testATokenIssuedInTheFutureIsRejected(): void
    {
        $this->expectExceptionMessageMatches('/future/i');
        $this->verify($this->factory->sign($this->claims(['iat' => $this->now + 600])));
    }

    public function testSmallClockSkewIsTolerated(): void
    {
        $claims = $this->verify($this->factory->sign($this->claims([
            'exp' => $this->now - 30,
            'iat' => $this->now + 30,
        ])));

        self::assertArrayHasKey('sub', $claims);
    }

    public function testAnAlgNoneTokenIsRejected(): void
    {
        $header = Pkce::base64UrlEncode((string) json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $payload = Pkce::base64UrlEncode((string) json_encode($this->claims()));

        $this->expectExceptionMessageMatches('/algorithm/i');
        $this->verify($header . '.' . $payload . '.');
    }

    public function testASymmetricAlgorithmIsRejected(): void
    {
        $this->expectExceptionMessageMatches('/algorithm/i');
        $this->verify($this->factory->sign($this->claims(), ['alg' => 'HS256']));
    }

    public function testClaimsTamperedWithAfterSigningAreRejected(): void
    {
        $this->expectExceptionMessageMatches('/signature/i');
        $this->verify($this->factory->signThenTamper($this->claims()));
    }

    public function testATokenSignedByAnotherKeyIsRejected(): void
    {
        $attacker = new JwtFactory('test-key');
        $token = $attacker->sign($this->claims());

        // Same key ID, different key material: the signature must not verify
        // against Google's published key.
        $this->expectExceptionMessageMatches('/signature/i');
        $this->verify($token);
    }

    public function testAnUnknownKeyIdIsRejected(): void
    {
        $this->expectExceptionMessageMatches('/key ID/i');
        $this->verify($this->factory->sign($this->claims(), ['kid' => 'not-a-google-key']));
    }

    public function testAMalformedTokenIsRejected(): void
    {
        $this->expectException(GoogleAuthException::class);
        $this->verify('this-is-not-a-jwt');
    }

    public function testATokenWithoutASubjectIsRejected(): void
    {
        $claims = $this->claims();
        unset($claims['sub']);

        $this->expectExceptionMessageMatches('/sub claim/i');
        $this->verify($this->factory->sign($claims));
    }
}
