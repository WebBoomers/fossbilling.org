<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Enum;

/**
 * The authentication modes an administrator can choose from.
 *
 * The default is intentionally {@see AuthMode::LoginOnly}: a freshly installed
 * extension must never be able to create FOSSBilling customers on its own.
 */
enum AuthMode: string
{
    case LoginOnly = 'login';
    case SignupOnly = 'signup';
    case Both = 'both';

    /**
     * The value used whenever configuration is missing, empty or invalid.
     */
    public const string DEFAULT_VALUE = 'login';

    /**
     * Never trust a submitted or stored value: anything unrecognised falls back
     * to the safest mode rather than throwing, so a corrupted configuration row
     * cannot silently enable account creation.
     */
    public static function fromConfigValue(mixed $value): self
    {
        if ($value instanceof self) {
            return $value;
        }

        if (!is_string($value)) {
            return self::LoginOnly;
        }

        return self::tryFrom(strtolower(trim($value))) ?? self::LoginOnly;
    }

    /**
     * Strict variant used when validating administrator input, so an invalid
     * submission is reported instead of being silently downgraded.
     */
    public static function isValidValue(mixed $value): bool
    {
        return is_string($value) && self::tryFrom(strtolower(trim($value))) instanceof self;
    }

    public function allowsLogin(): bool
    {
        return $this === self::LoginOnly || $this === self::Both;
    }

    public function allowsSignup(): bool
    {
        return $this === self::SignupOnly || $this === self::Both;
    }

    /**
     * Untranslated label. Callers pass it through the FOSSBilling translation
     * layer (`__trans()` / the `trans` Twig filter).
     */
    public function label(): string
    {
        return match ($this) {
            self::LoginOnly => 'Login Only',
            self::SignupOnly => 'Signup Only',
            self::Both => 'Login & Signup',
        };
    }

    /**
     * @return array<string, string> value => untranslated label
     */
    public static function options(): array
    {
        $options = [];
        foreach (self::cases() as $case) {
            $options[$case->value] = $case->label();
        }

        return $options;
    }
}
