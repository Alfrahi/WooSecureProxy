<?php
/**
 * Base test case wiring Brain Monkey into PHPUnit.
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Brain\Monkey;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

abstract class TestCase extends PHPUnitTestCase
{
    use MockeryPHPUnitIntegration;

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }
}
