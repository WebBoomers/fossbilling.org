<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Exception;

/**
 * Carries two separate messages on purpose.
 *
 * - The exception message is the technical detail, intended only for the
 *   FOSSBilling log. It may name the failing step but must never contain a
 *   client secret, an access token, an ID token or an authorization code.
 * - {@see getUserMessage()} is the short, untranslated sentence shown to the
 *   visitor. It must not disclose whether a particular account exists.
 */
class GoogleAuthException extends \RuntimeException
{
    private const string DEFAULT_USER_MESSAGE = 'Google authentication could not be completed. Please try again or use your usual login details.';

    /**
     * @param array<string, string> $userMessageParams placeholders for the translator
     */
    public function __construct(
        string $logMessage,
        private readonly string $userMessage = self::DEFAULT_USER_MESSAGE,
        private readonly array $userMessageParams = [],
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($logMessage, $code, $previous);
    }

    public function getUserMessage(): string
    {
        return $this->userMessage;
    }

    /**
     * @return array<string, string>
     */
    public function getUserMessageParams(): array
    {
        return $this->userMessageParams;
    }
}
