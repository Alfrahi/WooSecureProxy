<?php
/**
 * Unit tests for Metrics counters.
 *
 * @package WooSecureProxy\Tests\Unit
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use Brain\Monkey\Functions;
use WooSecureProxy\Helpers\Metrics;

final class MetricsTest extends TestCase {

	/** In-memory option store for get_option/update_option stubs. */
	private array $option_store = array();

	protected function setUp(): void {
		parent::setUp();

		$this->option_store = array();

		$store = &$this->option_store;
		Functions\when( 'get_option' )->alias(
			static function ( string $key, $default = false ) use ( &$store ) {
				return $store[ $key ] ?? $default;
			}
		);
		Functions\when( 'update_option' )->alias(
			static function ( string $key, $value ) use ( &$store ) {
				$store[ $key ] = $value;
				return true;
			}
		);
		Functions\when( 'delete_option' )->alias(
			static function ( string $key ) use ( &$store ) {
				unset( $store[ $key ] );
				return true;
			}
		);
	}

	public function test_record_increments_action_and_status_buckets(): void {
		Metrics::record( 'getProducts', 200 );
		Metrics::record( 'getProducts', 200 );
		Metrics::record( 'getProducts', 429 );
		Metrics::record( 'customerLogin', 401 );

		$summary = Metrics::summary();
		$day     = gmdate( 'Y-m-d' );

		$this->assertSame( 2, $summary[ $day ]['getProducts']['2xx'] );
		$this->assertSame( 1, $summary[ $day ]['getProducts']['4xx'] );
		$this->assertSame( 1, $summary[ $day ]['customerLogin']['4xx'] );
		$this->assertSame( 4, $summary[ $day ]['_total']['2xx'] + $summary[ $day ]['_total']['4xx'] );
	}

	public function test_summary_tolerates_missing_or_invalid_option(): void {
		$this->assertSame( array(), Metrics::summary() );

		$this->option_store[ Metrics::OPTION ] = 'garbage-not-an-array';
		$this->assertSame( array(), Metrics::summary() );
	}

	public function test_wipe_deletes_option(): void {
		Metrics::record( 'getProducts', 200 );
		$this->assertNotEmpty( Metrics::summary() );

		Metrics::wipe();
		$this->assertSame( array(), Metrics::summary() );
	}

	public function test_prunes_days_older_than_keep_window(): void {
		$old_day = gmdate( 'Y-m-d', time() - 10 * DAY_IN_SECONDS );

		$this->option_store[ Metrics::OPTION ] = array(
			$old_day => array( 'getProducts' => array( '2xx' => 99 ) ),
		);

		Metrics::record( 'getProducts', 200 );

		$summary = Metrics::summary();
		$this->assertArrayNotHasKey( $old_day, $summary );
		$this->assertSame( 1, $summary[ gmdate( 'Y-m-d' ) ]['getProducts']['2xx'] );
	}
}
