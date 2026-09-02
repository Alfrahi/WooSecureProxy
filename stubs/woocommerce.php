<?php
/**
 * Minimal WooCommerce stubs for PHPStan.
 *
 * The full WC stubs package is a heavy dependency for a plugin that only
 * touches three WooCommerce entry points; these declarations cover exactly
 * the API surface this plugin uses. Extend if new WC symbols are used.
 *
 * @package WooSecureProxy
 */

/**
 * Returns an order object, or false when the ID is invalid.
 *
 * @param mixed $the_order Post object or post ID of the order.
 */
function wc_get_order( $the_order ): WC_Order|false {
}

/**
 * Creates a new WooCommerce customer.
 *
 * @param string $email    Customer email.
 * @param string $username Customer username.
 * @param string $password Customer password.
 * @return int|WP_Error Customer ID on success.
 */
function wc_create_new_customer( string $email, string $username = '', string $password = '' ): int|WP_Error {
}

/**
 * Minimal WC_Order shape used by the proxy.
 */
class WC_Order {

	/**
	 * Returns the customer (user) ID of the order owner.
	 */
	public function get_customer_id(): int {
	}
}

/**
 * Minimal WC_Customer shape used by the proxy.
 */
class WC_Customer {

	/**
	 * Builds a customer object from ID, email, WP_User or the session.
	 *
	 * @param int|string|WP_User $customer Customer to load.
	 */
	public function __construct( $customer = 0 ) {
	}

	/**
	 * Returns the customer user ID.
	 */
	public function get_id(): int {
	}
}
