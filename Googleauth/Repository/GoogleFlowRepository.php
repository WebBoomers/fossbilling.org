<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Repository;

use Box\Mod\Googleauth\Entity\GoogleFlow;
use Doctrine\ORM\EntityRepository;

/**
 * @extends EntityRepository<GoogleFlow>
 */
class GoogleFlowRepository extends EntityRepository
{
    public function findByStateHash(string $stateHash): ?GoogleFlow
    {
        if ($stateHash === '') {
            return null;
        }

        return $this->findOneBy(['stateHash' => $stateHash]);
    }

    /**
     * Drop rows that are past their expiry. Called opportunistically whenever a
     * flow starts, so abandoned sign-ins do not accumulate.
     */
    public function deleteExpired(?\DateTimeImmutable $now = null): int
    {
        return (int) $this->createQueryBuilder('f')
            ->delete()
            ->where('f.expiresAt < :now')
            ->setParameter('now', $now ?? new \DateTimeImmutable())
            ->getQuery()
            ->execute();
    }

    public function deleteAll(): int
    {
        return (int) $this->createQueryBuilder('f')
            ->delete()
            ->getQuery()
            ->execute();
    }
}
