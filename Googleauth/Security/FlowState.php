<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Security;

use Box\Mod\Googleauth\Enum\FlowIntent;

/**
 * Everything the callback needs in order to finish a flow it did not start.
 *
 * Held server-side only. The browser carries just two opaque values: the `state`
 * in the URL, and the correlation token in a `SameSite=Lax` cookie. Only the
 * SHA-256 of the correlation token is kept here, so the stored record cannot be
 * replayed by anyone who can read it.
 */
final class FlowState
{
    public function __construct(
        public readonly string $state,
        public readonly string $correlationHash,
        public readonly string $nonce,
        public readonly string $codeVerifier,
        public readonly FlowIntent $intent,
        public readonly string $returnTo,
        public readonly int $createdAt,
        /** Set only for the "link" intent: the customer who must still be the one signed in when the callback lands. */
        public readonly ?int $clientId = null,
    ) {
    }

    public function isExpired(int $now, int $lifetimeSeconds): bool
    {
        return $now - $this->createdAt > $lifetimeSeconds || $this->createdAt > $now + 60;
    }

    public function matchesCorrelation(mixed $providedToken): bool
    {
        if (!is_string($providedToken) || $providedToken === '' || $this->correlationHash === '') {
            return false;
        }

        return hash_equals($this->correlationHash, hash('sha256', $providedToken));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'correlation_hash' => $this->correlationHash,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'intent' => $this->intent->value,
            'return_to' => $this->returnTo,
            'created_at' => $this->createdAt,
            'client_id' => $this->clientId,
        ];
    }

    /**
     * @param array<string, mixed>|mixed $data
     */
    public static function fromArray(mixed $data): ?self
    {
        if (!is_array($data)) {
            return null;
        }

        $intent = FlowIntent::tryFromValue($data['intent'] ?? null);
        $state = $data['state'] ?? null;
        $nonce = $data['nonce'] ?? null;
        $verifier = $data['code_verifier'] ?? null;
        $correlation = $data['correlation_hash'] ?? null;

        if (!$intent instanceof FlowIntent || !is_string($state) || !is_string($nonce) || !is_string($verifier) || !is_string($correlation)) {
            return null;
        }

        $clientId = $data['client_id'] ?? null;

        return new self(
            $state,
            $correlation,
            $nonce,
            $verifier,
            $intent,
            is_string($data['return_to'] ?? null) ? $data['return_to'] : '/',
            is_int($data['created_at'] ?? null) ? $data['created_at'] : 0,
            is_int($clientId) ? $clientId : null,
        );
    }
}
