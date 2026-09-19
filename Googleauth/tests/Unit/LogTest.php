<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Tests\Unit;

use Box\Mod\Googleauth\Support\Log;
use PHPUnit\Framework\TestCase;

/**
 * Regression cover for the FOSSBilling 0.8.x / main logger split.
 *
 * The legacy Box_Log turns any unknown method name into a log priority, so
 * calling withChannel() on it threw "Bad log priority" and took the whole OAuth
 * callback down. These tests pin the behaviour that replaced it.
 *
 * The spies record into a shared \ArrayObject because the helper clones the
 * logger before scoping it - a plain property would be written on the clone and
 * the assertions would never see it.
 */
final class LogTest extends TestCase
{
    private function container(?object $logger): \ArrayObject
    {
        return new \ArrayObject($logger === null ? [] : ['logger' => $logger]);
    }

    public function testModernLoggerGetsAChannelAndRawContext(): void
    {
        $logger = new ModernLoggerSpy();

        Log::info($this->container($logger), 'Client #{client_id} signed in', ['client_id' => 7]);

        self::assertSame('googleauth', $logger->record['channel']);
        self::assertSame('info', $logger->record['level']);
        self::assertSame('Client #{client_id} signed in', $logger->record['message']);
        self::assertSame(['client_id' => 7], $logger->record['context']);
    }

    public function testLegacyLoggerIsNeverAskedForAChannelMethodItDoesNotHave(): void
    {
        $logger = new LegacyLoggerSpy();

        Log::warning($this->container($logger), 'Something went wrong');

        self::assertSame('warning', $logger->record['level']);
        self::assertFalse($logger->record['sawUnknownMethod'], 'withChannel() must not be called on the legacy logger.');
    }

    public function testLegacyLoggerGetsAnInterpolatedSingleStringNotSprintfArguments(): void
    {
        $logger = new LegacyLoggerSpy();

        Log::info($this->container($logger), 'Client #{client_id} connected {email}', [
            'client_id' => 42,
            'email' => 'customer@example.com',
        ]);

        self::assertSame('Client #42 connected customer@example.com', $logger->record['message']);
        self::assertSame([], $logger->record['extraArgs'], 'The legacy logger would treat extra arguments as sprintf values.');
    }

    public function testLegacyLoggerIsScopedToTheGoogleauthChannel(): void
    {
        $logger = new LegacyLoggerSpy();

        Log::info($this->container($logger), 'hello');

        self::assertSame('googleauth', $logger->record['channelAtWrite']);
    }

    public function testTheSharedLoggerInstanceIsNotMutated(): void
    {
        $logger = new LegacyLoggerSpy();

        Log::info($this->container($logger), 'hello');

        self::assertSame(
            'application',
            $logger->channel,
            'setChannel() must be applied to a clone - the container shares one logger for the whole request.'
        );
    }

    public function testNonScalarContextValuesAreLeftAlone(): void
    {
        $logger = new LegacyLoggerSpy();

        Log::debug($this->container($logger), 'Payload {data} for {id}', ['data' => ['a' => 1], 'id' => 3]);

        self::assertSame('Payload {data} for 3', $logger->record['message']);
    }

    public function testAThrowingLoggerNeverBreaksTheCaller(): void
    {
        $logger = new ExplodingLoggerSpy();

        Log::error($this->container($logger), 'this must not bubble up');

        self::assertTrue($logger->called, 'The logger was called...');
        // ...and the exception it threw did not escape, which is the assertion
        // that matters: logging must never break authentication.
    }

    public function testAMissingContainerOrLoggerIsSilentlyIgnored(): void
    {
        Log::info(null, 'no container at all');
        Log::info($this->container(null), 'container with no logger');

        self::expectNotToPerformAssertions();
    }
}

/**
 * Stands in for FOSSBilling\Logger (current main): PSR-3, with channels.
 */
final class ModernLoggerSpy
{
    public \ArrayObject $record;
    public ?string $channel = null;

    public function __construct(?\ArrayObject $record = null)
    {
        $this->record = $record ?? new \ArrayObject([
            'channel' => null,
            'level' => null,
            'message' => null,
            'context' => null,
        ]);
    }

    public function withChannel(string $channel): self
    {
        $scoped = clone $this;
        $scoped->channel = $channel;

        return $scoped;
    }

    public function __call(string $method, array $arguments): void
    {
        $this->record['channel'] = $this->channel;
        $this->record['level'] = $method;
        $this->record['message'] = $arguments[0] ?? null;
        $this->record['context'] = $arguments[1] ?? [];
    }
}

/**
 * Stands in for Box_Log (FOSSBilling 0.8.x): setChannel(), and __call() treats
 * any unknown method name as a log priority.
 */
final class LegacyLoggerSpy
{
    private const array PRIORITIES = ['info', 'warning', 'error', 'debug', 'notice', 'critical', 'alert', 'emergency'];

    public \ArrayObject $record;
    public string $channel = 'application';

    public function __construct()
    {
        $this->record = new \ArrayObject([
            'level' => null,
            'message' => null,
            'extraArgs' => [],
            'channelAtWrite' => null,
            'sawUnknownMethod' => false,
        ]);
    }

    public function setChannel(string $channel): static
    {
        $this->channel = $channel;

        return $this;
    }

    public function __call(string $method, array $arguments): void
    {
        // Mirror Box_Log: anything that is not a real priority blows up.
        if (!in_array($method, self::PRIORITIES, true)) {
            $this->record['sawUnknownMethod'] = true;

            throw new \RuntimeException('Bad log priority');
        }

        $this->record['level'] = $method;
        $this->record['message'] = $arguments[0] ?? null;
        $this->record['extraArgs'] = array_slice($arguments, 1);
        $this->record['channelAtWrite'] = $this->channel;
    }
}

final class ExplodingLoggerSpy
{
    public bool $called = false;

    public function __call(string $method, array $arguments): void
    {
        $this->called = true;

        throw new \RuntimeException('the logging backend is down');
    }
}
