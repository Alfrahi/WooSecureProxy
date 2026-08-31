<?php
/**
 * Harness smoke test: proves PHPUnit + Brain Monkey run.
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use Brain\Monkey\Functions;

final class SanityTest extends TestCase
{
    public function test_harness_runs(): void
    {
        $this->assertTrue(true);
    }

    public function test_brain_monkey_stubs_wp_functions(): void
    {
        Functions\when('esc_html')->returnArg();

        $this->assertSame('hello', \esc_html('hello'));
    }
}
