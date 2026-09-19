<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Security;

use Box\Mod\Googleauth\Entity\GoogleFlow;
use Box\Mod\Googleauth\Enum\FlowIntent;
use Box\Mod\Googleauth\Repository\GoogleFlowRepository;
use Box\Mod\Googleauth\Support\Log;

/**
 * Pending flows, in the extension's own `googleauth_flow` table.
 *
 * The database is used rather than the cache because a sign-in must not depend
 * on which cache backend an administrator happens to have configured - a
 * per-process cache would lose the flow between the redirect and the callback.
 */
final class DoctrineFlowStorage implements FlowStorageInterface
{
    public function __construct(private readonly \Pimple\Container $di)
    {
    }

    private function repository(): GoogleFlowRepository
    {
        /** @var GoogleFlowRepository $repository */
        $repository = $this->di['em']->getRepository(GoogleFlow::class);

        return $repository;
    }

    public function put(FlowState $state, int $ttlSeconds): void
    {
        // Housekeeping: abandoned sign-ins are cleared out as new ones start.
        try {
            $this->repository()->deleteExpired();
        } catch (\Throwable $e) {
            Log::debug($this->di, 'Could not prune expired Google sign-in flows: ' . $e->getMessage());
        }

        $row = new GoogleFlow();
        $row->setStateHash(GoogleFlow::hash($state->state))
            ->setCorrelationHash($state->correlationHash)
            ->setNonce($state->nonce)
            ->setCodeVerifier($state->codeVerifier)
            ->setIntent($state->intent->value)
            ->setReturnTo($state->returnTo)
            ->setClientId($state->clientId)
            ->setExpiresAt(new \DateTimeImmutable('@' . ($state->createdAt + $ttlSeconds)));

        $this->di['em']->persist($row);
        $this->di['em']->flush();
    }

    public function take(string $state): ?FlowState
    {
        if ($state === '') {
            return null;
        }

        $row = $this->repository()->findByStateHash(GoogleFlow::hash($state));
        if (!$row instanceof GoogleFlow) {
            return null;
        }

        $intent = FlowIntent::tryFromValue($row->getIntent());

        $flow = $intent instanceof FlowIntent
            ? new FlowState(
                $state,
                $row->getCorrelationHash(),
                $row->getNonce(),
                $row->getCodeVerifier(),
                $intent,
                $row->getReturnTo(),
                $row->getCreatedAt()->getTimestamp(),
                $row->getClientId(),
            )
            : null;

        // Single use: the row goes whether or not the caller ends up accepting
        // it, so a captured callback URL cannot be replayed.
        $this->di['em']->remove($row);
        $this->di['em']->flush();

        return $flow;
    }

    public function discard(string $state): void
    {
        try {
            $this->take($state);
        } catch (\Throwable $e) {
            Log::debug($this->di, 'Could not discard a pending Google sign-in flow: ' . $e->getMessage());
        }
    }
}
