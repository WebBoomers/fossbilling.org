<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Security;

/**
 * Open redirect protection for the "where should I land afterwards?" parameter.
 *
 * The flow only ever redirects to a path *inside* this FOSSBilling install. A
 * candidate is accepted only when it is an ordinary relative path; anything that
 * could resolve to another origin (a scheme, a protocol-relative `//host`, a
 * backslash, an encoded newline, a userinfo `@`) is discarded in favour of the
 * fallback. The result is a path, never an absolute URL, and is handed to
 * FOSSBilling's own URL builder which prefixes the configured system URL.
 */
final class ReturnUrlGuard
{
    public const string DEFAULT_PATH = '/';

    public static function sanitize(mixed $candidate, string $fallback = self::DEFAULT_PATH): string
    {
        if (!is_string($candidate)) {
            return $fallback;
        }

        // Reject control characters before trimming, not after: trim() strips
        // NUL, CR, LF and friends by default, which would quietly turn a
        // smuggling attempt into an innocent-looking path instead of rejecting
        // it.
        if (preg_match('/[\x00-\x1F\x7F]/', $candidate) === 1) {
            return $fallback;
        }

        $value = trim($candidate);
        if ($value === '') {
            return $fallback;
        }

        $decoded = rawurldecode($value);
        if (preg_match('/[\x00-\x1F\x7F]/', $decoded) === 1) {
            return $fallback;
        }

        // Backslashes are treated as path separators by some browsers.
        if (str_contains($value, '\\') || str_contains($decoded, '\\')) {
            return $fallback;
        }

        // Must be relative to this site: no scheme, no protocol-relative host.
        if (!str_starts_with($value, '/') || str_starts_with($value, '//')) {
            return $fallback;
        }

        if (preg_match('#^/+[^/]*:#', $value) === 1) {
            return $fallback;
        }

        $path = parse_url($value, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return $fallback;
        }

        // Directory traversal has no legitimate use in a client-area link.
        foreach (explode('/', $path) as $segment) {
            if ($segment === '..' || $segment === '.') {
                return $fallback;
            }
        }

        $query = parse_url($value, PHP_URL_QUERY);
        $result = $path;
        if (is_string($query) && $query !== '') {
            $result .= '?' . $query;
        }

        return $result;
    }

    /**
     * FOSSBilling's Url::link() trims leading slashes; this returns the value in
     * the shape that helper expects.
     */
    public static function toLinkPath(string $sanitizedPath): string
    {
        return ltrim($sanitizedPath, '/');
    }
}
