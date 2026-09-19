<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Support;

/**
 * Version-safe logging.
 *
 * FOSSBilling has two different loggers depending on the release:
 *
 *  - 0.8.x ships the legacy `Box_Log`, whose `__call()` treats *any* unknown
 *    method name as a log priority. Calling `withChannel()` on it therefore
 *    throws "Bad log priority" rather than returning a channel-scoped logger.
 *    It offers `setChannel()` instead, and it runs extra arguments through
 *    `vsprintf()`, so PSR-style `{placeholder}` context is not interpolated.
 *  - Newer releases ship `FOSSBilling\Logger`, a PSR-3 logger with
 *    `withChannel()` and proper context interpolation.
 *
 * This helper detects which one is present and speaks to it correctly, so the
 * extension logs the same way on both.
 *
 * Every call is wrapped in a catch-all. Logging is diagnostics; it must never
 * be the reason a customer cannot sign in.
 */
final class Log
{
    public const string CHANNEL = 'googleauth';

    /**
     * @param array<string, mixed> $context
     */
    public static function info(?\ArrayAccess $di, string $message, array $context = []): void
    {
        self::write($di, 'info', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function warning(?\ArrayAccess $di, string $message, array $context = []): void
    {
        self::write($di, 'warning', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function error(?\ArrayAccess $di, string $message, array $context = []): void
    {
        self::write($di, 'error', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function debug(?\ArrayAccess $di, string $message, array $context = []): void
    {
        self::write($di, 'debug', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function write(?\ArrayAccess $di, string $level, string $message, array $context): void
    {
        try {
            if ($di === null || !isset($di['logger'])) {
                return;
            }

            $logger = $di['logger'];

            // Modern PSR-3 logger: returns a channel-scoped copy and
            // interpolates {placeholders} itself.
            if (method_exists($logger, 'withChannel')) {
                $logger->withChannel(self::CHANNEL)->{$level}($message, $context);

                return;
            }

            // Legacy Box_Log. setChannel() mutates, and the container shares one
            // logger instance for the whole request, so work on a clone to avoid
            // leaving every later log line stamped with our channel. Context is
            // interpolated here because the legacy logger would otherwise treat
            // it as sprintf arguments.
            $interpolated = self::interpolate($message, $context);

            if (method_exists($logger, 'setChannel')) {
                $scoped = clone $logger;
                $scoped->setChannel(self::CHANNEL);
                $scoped->{$level}($interpolated);

                return;
            }

            $logger->{$level}($interpolated);
        } catch (\Throwable) {
            // A logger that cannot log is not worth failing a request over.
        }
    }

    /**
     * Replace PSR-3 style {placeholders} with their context values.
     *
     * @param array<string, mixed> $context
     */
    private static function interpolate(string $message, array $context): string
    {
        if ($context === []) {
            return $message;
        }

        $replacements = [];
        foreach ($context as $key => $value) {
            if (!is_scalar($value) && !($value instanceof \Stringable) && $value !== null) {
                continue;
            }

            $replacements['{' . $key . '}'] = (string) $value;
        }

        return $replacements === [] ? $message : strtr($message, $replacements);
    }
}
