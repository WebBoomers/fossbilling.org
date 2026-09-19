<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Auth;

/**
 * What the controller should do once a flow has been decided: where to send the
 * visitor, and what to tell them.
 *
 * Messages are untranslated English source strings; the controller passes them
 * through `__trans()` before they are shown.
 */
final class FlowResult
{
    public const string TYPE_SUCCESS = 'success';
    public const string TYPE_INFO = 'info';
    public const string TYPE_ERROR = 'error';

    private function __construct(
        public readonly string $redirectPath,
        public readonly string $message,
        public readonly string $type,
    ) {
    }

    public static function success(string $redirectPath, string $message = ''): self
    {
        return new self($redirectPath, $message, self::TYPE_SUCCESS);
    }

    public static function info(string $redirectPath, string $message): self
    {
        return new self($redirectPath, $message, self::TYPE_INFO);
    }

    public static function error(string $redirectPath, string $message): self
    {
        return new self($redirectPath, $message, self::TYPE_ERROR);
    }

    public function hasMessage(): bool
    {
        return trim($this->message) !== '';
    }
}
