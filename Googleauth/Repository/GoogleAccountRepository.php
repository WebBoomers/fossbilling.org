<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Repository;

use Box\Mod\Googleauth\Entity\GoogleAccount;
use Doctrine\ORM\EntityRepository;

/**
 * Every lookup goes through parameterised DQL/criteria, so no value coming from
 * Google or from a request is ever concatenated into SQL.
 *
 * @extends EntityRepository<GoogleAccount>
 */
class GoogleAccountRepository extends EntityRepository
{
    public function findByGoogleSub(string $googleSub): ?GoogleAccount
    {
        if ($googleSub === '') {
            return null;
        }

        return $this->findOneBy(['googleSub' => $googleSub]);
    }

    public function findByClientId(int $clientId): ?GoogleAccount
    {
        if ($clientId <= 0) {
            return null;
        }

        return $this->findOneBy(['clientId' => $clientId]);
    }

    public function countLinks(): int
    {
        return (int) $this->createQueryBuilder('a')
            ->select('COUNT(a.id)')
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * @return list<GoogleAccount>
     */
    public function findRecent(int $limit = 25): array
    {
        return $this->createQueryBuilder('a')
            ->orderBy('a.createdAt', 'DESC')
            ->setMaxResults(max(1, min($limit, 100)))
            ->getQuery()
            ->getResult();
    }

    public function deleteByClientId(int $clientId): int
    {
        if ($clientId <= 0) {
            return 0;
        }

        return (int) $this->createQueryBuilder('a')
            ->delete()
            ->where('a.clientId = :clientId')
            ->setParameter('clientId', $clientId)
            ->getQuery()
            ->execute();
    }

    public function deleteAll(): int
    {
        return (int) $this->createQueryBuilder('a')
            ->delete()
            ->getQuery()
            ->execute();
    }
}
