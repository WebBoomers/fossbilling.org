<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Enum\FlowIntent;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\OAuth\Pkce;
use Box\Mod\Googleauth\OAuth\StateToken;
use Box\Mod\Googleauth\Security\FlowState;
use Box\Mod\Googleauth\Security\FlowStateStore;
use Box\Mod\Googleauth\Tests\Support\ArrayFlowStorage;
use PHPUnit\Framework\TestCase;

final class FlowStateStoreTest extends TestCase
{
    private ArrayFlowStorage $storage;
    private FlowStateStore $store;
    private string $correlation;

    protected function setUp(): void
    {
        $this->storage = new ArrayFlowStorage();
        $this->store = new FlowStateStore($this->storage);
        $this->correlation = StateToken::generate();
    }

    private function storeFlow(
        FlowIntent $intent = FlowIntent::Login,
        ?int $createdAt = null,
        ?int $clientId = null,
        ?string $correlation = null,
    ): FlowState {
        $state = new FlowState(
            StateToken::generate(),
            hash('sha256', $correlation ?? $this->correlation),
            StateToken::generate(),
            Pkce::create()->verifier,
            $intent,
            '/client/profile',
            $createdAt ?? time(),
            $clientId,
        );

        $this->store->store($state);

        return $state;
    }

    public function testAValidCallbackReturnsTheStoredFlow(): void
    {
        $stored = $this->storeFlow(FlowIntent::Link, clientId: 42);

        $consumed = $this->store->consume($stored->state, $this->correlation);

        self::assertSame($stored->state, $consumed->state);
        self::assertSame($stored->nonce, $consumed->nonce);
        self::assertSame($stored->codeVerifier, $consumed->codeVerifier);
        self::assertSame(FlowIntent::Link, $consumed->intent);
        self::assertSame('/client/profile', $consumed->returnTo);
        self::assertSame(42, $consumed->clientId);
    }

    public function testTheSameStateCannotBeUsedTwice(): void
    {
        $stored = $this->storeFlow();

        $this->store->consume($stored->state, $this->correlation);

        $this->expectException(GoogleAuthException::class);
        $this->store->consume($stored->state, $this->correlation);
    }

    public function testAMismatchedStateIsRejected(): void
    {
        $this->storeFlow();

        $this->expectException(GoogleAuthException::class);
        $this->store->consume(StateToken::generate(), $this->correlation);
    }

    /**
     * The attack this defends against: somebody completes a Google sign-in on
     * their own machine, then walks a victim's browser through the resulting
     * callback URL to sign the victim into the attacker's account. The victim's
     * browser has no matching correlation cookie, so the callback is refused.
     */
    public function testACallbackFromADifferentBrowserIsRejected(): void
    {
        $stored = $this->storeFlow();

        try {
            $this->store->consume($stored->state, StateToken::generate());
            self::fail('A callback without the matching correlation cookie must be rejected.');
        } catch (GoogleAuthException $e) {
            self::assertStringContainsString('browser', $e->getUserMessage());
        }
    }

    public function testACallbackWithNoCorrelationCookieIsRejected(): void
    {
        $stored = $this->storeFlow();

        $this->expectException(GoogleAuthException::class);
        $this->store->consume($stored->state, null);
    }

    public function testAFailedCorrelationCheckStillBurnsTheFlow(): void
    {
        $stored = $this->storeFlow();

        try {
            $this->store->consume($stored->state, StateToken::generate());
        } catch (GoogleAuthException) {
            // expected
        }

        self::assertTrue($this->storage->isEmpty(), 'A rejected callback must not leave the flow available for a retry.');
    }

    public function testAMissingOrMalformedStateIsRejected(): void
    {
        $this->storeFlow();

        foreach ([null, '', 'not-a-state', ['array'], 12345] as $bogus) {
            try {
                $this->store->consume($bogus, $this->correlation);
                self::fail('A malformed state must be rejected: ' . var_export($bogus, true));
            } catch (GoogleAuthException) {
                // expected
            }
        }
    }

    public function testACallbackWithNoPendingFlowIsRejected(): void
    {
        $this->expectException(GoogleAuthException::class);
        $this->store->consume(StateToken::generate(), $this->correlation);
    }

    public function testAnExpiredFlowIsRejected(): void
    {
        $stored = $this->storeFlow(createdAt: time() - (FlowStateStore::LIFETIME_SECONDS + 5));

        $this->expectException(GoogleAuthException::class);
        $this->store->consume($stored->state, $this->correlation);
    }

    public function testAFlowInsideTheLifetimeIsAccepted(): void
    {
        $stored = $this->storeFlow(createdAt: time() - (FlowStateStore::LIFETIME_SECONDS - 5));

        self::assertSame($stored->state, $this->store->consume($stored->state, $this->correlation)->state);
    }

    public function testDiscardRemovesThePendingFlow(): void
    {
        $stored = $this->storeFlow();
        $this->store->discard($stored->state);

        self::assertTrue($this->storage->isEmpty());
    }

    public function testTheCorrelationCookieIsLaxScopedByName(): void
    {
        // Pinning the name: the cookie has to be SameSite=Lax, because a
        // SameSite=Strict cookie (which is what FOSSBilling uses for its own
        // session) is not sent on the top-level return navigation from Google.
        self::assertSame('googleauth_flow', FlowStateStore::COOKIE_NAME);
    }
}
