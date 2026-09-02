<?php
/**
 * PHPStan bootstrap: defines plugin constants that only exist at runtime
 * (set by woo-secure-proxy.php and WordPress core) so static analysis can
 * see them without loading WordPress.
 *
 * @package WooSecureProxy
 */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}
if ( ! defined( 'WSP_PATH' ) ) {
	define( 'WSP_PATH', __DIR__ . '/' );
}
if ( ! defined( 'WSP_URL' ) ) {
	define( 'WSP_URL', 'https://example.test/wp-content/plugins/woo-secure-proxy/' );
}
if ( ! defined( 'WSP_VERSION' ) ) {
	define( 'WSP_VERSION', '1.0.0' );
}
