<?php

declare(strict_types=1);

/**
 * php-scoper configuration for release builds.
 *
 * Only the vendored dependency tree is prefixed (currently firebase/php-jwt);
 * the plugin's own namespace is intentionally untouched.
 *
 * @package WooSecureProxy
 */

return array(
	'prefix'             => 'WooSecureProxy\\Vendor',
	// Everything in vendor/ gets prefixed; the whitelist keeps the plugin's
	// own autoload section untouched.
	'exclude-namespaces' => array( 'WooSecureProxy' ),
	'exclude-files'      => array(),
	'patchers'           => array(),
);
