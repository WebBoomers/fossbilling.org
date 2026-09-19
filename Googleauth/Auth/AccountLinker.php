<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Auth;

use Box\Mod\Client\Entity\Client;
use Box\Mod\Googleauth\Entity\GoogleAccount;
use Box\Mod\Googleauth\Exception\GoogleAuthException;
use Box\Mod\Googleauth\Google\GoogleIdentity;
use Box\Mod\Googleauth\Repository\GoogleAccountRepository;
use Box\Mod\Googleauth\Support\Log;

/**
 * Creates, reads and removes the Google identity <-> customer mapping.
 *
 * Two rules are enforced here and nowhere else, so there is a single place to
 * audit:
 *
 *  1. one Google identity maps to at most one customer;
 *  2. one customer maps to at most one Google identity.
 *
 * Both are also enforced by unique indexes, so a race between two concurrent
 * requests ends in a database error rather than a duplicate link.
 */
final class AccountLinker
{
    public function __construct(private readonly \Pimple\Container $di)
    {
    }

    private function repository(): GoogleAccountRepository
    {
        /** @var GoogleAccountRepository $repository */
        $repository = $this->di['em']->getRepository(GoogleAccount::class);

        return $repository;
    }

    public function findBySubject(string $googleSub): ?GoogleAccount
    {
        return $this->repository()->findByGoogleSub($googleSub);
    }

    public function findByClientId(int $clientId): ?GoogleAccount
    {
        return $this->repository()->findByClientId($clientId);
    }

    public function findClientForSubject(string $googleSub): ?Client
    {
        $link = $this->findBySubject($googleSub);
        if (!$link instanceof GoogleAccount) {
            return null;
        }

        $client = $this->di['em']->getRepository(Client::class)->find($link->getClientId());

        if (!$client instanceof Client) {
            // The customer was deleted without the mapping being cleaned up.
            Log::warning($this->di, 
                'Removing a Google account link that points at missing client #{client_id}.',
                ['client_id' => $link->getClientId()]
            );
            $this->di['em']->remove($link);
            $this->di['em']->flush();

            return null;
        }

        return $client;
    }

    /**
     * Attach a verified Google identity to a customer.
     *
     * The caller is responsible for having established that the customer is the
     * authenticated one - this method never decides *who* may be linked.
     */
    public function link(int $clientId, GoogleIdentity $identity): GoogleAccount
    {
        if ($clientId <= 0) {
            throw new GoogleAuthException('Refused to create a Google account link without a customer.');
        }

        $existingForSubject = $this->findBySubject($identity->subject);
        if ($existingForSubject instanceof GoogleAccount) {
            if ($existingForSubject->getClientId() === $clientId) {
                return $existingForSubject;
            }

            throw new GoogleAuthException(
                sprintf('Refused to link Google identity already mapped to client #%d onto client #%d.', $existingForSubject->getClientId(), $clientId),
                'That Google account is already connected to another account on this site.',
            );
        }

        if ($this->findByClientId($clientId) instanceof GoogleAccount) {
            throw new GoogleAuthException(
                sprintf('Client #%d already has a Google account connected.', $clientId),
                'Your account is already connected to a Google account. Disconnect it first if you want to use a different one.',
            );
        }

        $link = new GoogleAccount();
        $link->setClientId($clientId)
            ->setGoogleSub($identity->subject)
            ->setGoogleEmail($identity->email);

        try {
            $this->di['em']->persist($link);
            $this->di['em']->flush();
        } catch (\Throwable $e) {
            throw new GoogleAuthException(
                'Failed to store the Google account link: ' . $e->getMessage(),
                'Your Google account could not be connected right now. Please try again.',
                previous: $e,
            );
        }

        Log::info($this->di, 'Connected a Google account to client #{client_id}', ['client_id' => $clientId]);

        return $link;
    }

    /**
     * Record a successful sign-in and keep the stored email in step with Google.
     */
    public function recordLogin(GoogleAccount $link, GoogleIdentity $identity): void
    {
        $link->touchLastLogin();
        if ($link->getGoogleEmail() !== $identity->email) {
            $link->setGoogleEmail($identity->email);
        }

        try {
            $this->di['em']->flush();
        } catch (\Throwable $e) {
            // Bookkeeping only - never fail a valid login because of it.
            Log::debug($this->di, 'Could not update the Google account link after login: ' . $e->getMessage());
        }
    }

    /**
     * Find the single active customer holding this email address.
     *
     * Only ever called when the administrator has switched on
     * "link by verified email"; on its own an address proves nothing. Returns
     * null when no customer matches, or when more than one does - an ambiguous
     * match must never be resolved by guessing.
     */
    public function findActiveClientByEmail(string $email): ?Client
    {
        $email = strtolower(trim($email));
        if ($email === '') {
            return null;
        }

        $matches = $this->di['em']->getRepository(Client::class)->findBy([
            'email' => $email,
            'status' => Client::ACTIVE,
        ], limit: 2);

        return count($matches) === 1 ? $matches[0] : null;
    }

    public function unlink(int $clientId): bool
    {
        $link = $this->findByClientId($clientId);
        if (!$link instanceof GoogleAccount) {
            return false;
        }

        $this->di['em']->remove($link);
        $this->di['em']->flush();

        Log::info($this->di, 'Disconnected the Google account of client #{client_id}', ['client_id' => $clientId]);

        return true;
    }
}
