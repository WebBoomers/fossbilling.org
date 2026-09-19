<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Support;

use Box\Mod\Googleauth\Security\FlowState;
use Box\Mod\Googleauth\Security\FlowStorageInterface;

/**
 * In-memory flow storage for tests, with the same single-use semantics as the
 * database-backed implementation: take() removes the record.
 */
final class ArrayFlowStorage implements FlowStorageInterface
{
    /** @var array<string, FlowState> */
    private array $flows = [];

    public function put(FlowState $state, int $ttlSeconds): void
    {
        $this->flows[hash('sha256', $state->state)] = $state;
    }

    public function take(string $state): ?FlowState
    {
        $key = hash('sha256', $state);
        $found = $this->flows[$key] ?? null;
        unset($this->flows[$key]);

        return $found;
    }

    public function discard(string $state): void
    {
        unset($this->flows[hash('sha256', $state)]);
    }

    public function isEmpty(): bool
    {
        return $this->flows === [];
    }
}
