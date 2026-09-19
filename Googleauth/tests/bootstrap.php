<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling - standalone test bootstrap.
 *
 * The classes exercised here are deliberately free of FOSSBilling dependencies,
 * so the suite runs on its own with nothing but Composer's autoloader. The same
 * files are also picked up by FOSSBilling's own `composer test` when the module
 * is installed at `src/modules/Googleauth`, because Pest runs PHPUnit test
 * classes as-is.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

$autoloadCandidates = [
    __DIR__ . '/../vendor/autoload.php',
    // When the module lives inside a FOSSBilling checkout.
    __DIR__ . '/../../../vendor/autoload.php',
];

foreach ($autoloadCandidates as $candidate) {
    if (is_file($candidate)) {
        require_once $candidate;

        break;
    }
}

if (!class_exists(\Box\Mod\Googleauth\Enum\AuthMode::class, false)) {
    // Minimal PSR-4 fallback so the suite also runs from a plain checkout with
    // no Composer install (for example in a quick CI lint job).
    spl_autoload_register(static function (string $class): void {
        $prefixes = [
            'Box\\Mod\\Googleauth\\Tests\\' => __DIR__ . '/',
            'Box\\Mod\\Googleauth\\' => __DIR__ . '/../',
        ];

        foreach ($prefixes as $prefix => $baseDir) {
            if (!str_starts_with($class, $prefix)) {
                continue;
            }

            $relative = substr($class, strlen($prefix));
            $file = $baseDir . str_replace('\\', '/', $relative) . '.php';

            if (is_file($file)) {
                require_once $file;

                return;
            }
        }
    });
}
