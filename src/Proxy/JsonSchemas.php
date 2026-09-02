<?php
/**
 * Per-action JSON Schemas for proxy request `data` payloads.
 *
 * Write paths (createOrder/updateOrder, auth endpoints) are strict:
 * additionalProperties is false and required fields are enforced.
 * Read paths accept the loose query-param mapping but still constrain types.
 *
 * @package WooSecureProxy\Proxy
 * @since   1.0.0
 */

namespace WooSecureProxy\Proxy;

/**
 * Static schema map, action name → JSON Schema (as PHP array).
 *
 * @since 1.0.0
 */
final class JsonSchemas {

	/**
	 * Returns the schema for an action, or null when the action has no schema
	 * (schema-less actions are intentionally unconstrained).
	 *
	 * @param string $action Proxy action name.
	 * @return array<string, mixed>|null
	 * @since  1.0.0
	 */
	public static function for_action( string $action ): ?array {
		return self::schemas()[ $action ] ?? null;
	}

	/**
	 * The full action → schema map.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function schemas(): array {
		$int_id = array(
			'type'    => 'integer',
			'minimum' => 1,
		);

		// Read paths mirror WooCommerce's flexible query-params API: any scalar
		// param is allowed, nested arrays/objects are rejected (Prompt 9).
		$read_query = array(
			'type'                 => 'object',
			'properties'           => array(
				'id' => $int_id,
			),
			'additionalProperties' => array(
				'type' => array( 'string', 'integer', 'number', 'boolean', 'null' ),
			),
		);

		$person = array(
			'type'                 => 'object',
			'additionalProperties' => false,
			'properties'           => array(
				'first_name' => array( 'type' => 'string' ),
				'last_name'  => array( 'type' => 'string' ),
				'company'    => array( 'type' => 'string' ),
				'address_1'  => array( 'type' => 'string' ),
				'address_2'  => array( 'type' => 'string' ),
				'city'       => array( 'type' => 'string' ),
				'state'      => array( 'type' => 'string' ),
				'postcode'   => array( 'type' => 'string' ),
				'country'    => array( 'type' => 'string' ),
				'email'      => array(
					'type'   => 'string',
					'format' => 'email',
				),
				'phone'      => array( 'type' => 'string' ),
			),
		);

		$line_item = array(
			'type'                 => 'object',
			'required'             => array( 'product_id', 'quantity' ),
			'additionalProperties' => false,
			'properties'           => array(
				'product_id'   => $int_id,
				'variation_id' => $int_id,
				'quantity'     => array(
					'type'    => 'integer',
					'minimum' => 1,
				),
				'name'         => array( 'type' => 'string' ),
				'subtotal'     => array( 'type' => 'string' ),
				'total'        => array( 'type' => 'string' ),
			),
		);

		$money_item = array(
			'type'                 => 'object',
			'required'             => array( 'total' ),
			'additionalProperties' => false,
			'properties'           => array(
				'method_id'    => array( 'type' => 'string' ),
				'method_title' => array( 'type' => 'string' ),
				'total'        => array( 'type' => 'string' ),
			),
		);

		$order_write = array(
			'type'                 => 'object',
			'additionalProperties' => false,
			'properties'           => array(
				'id'                   => $int_id,
				'status'               => array(
					'type' => 'string',
					'enum' => array( 'pending', 'processing', 'on-hold', 'completed', 'cancelled', 'refunded', 'failed' ),
				),
				'currency'             => array(
					'type'      => 'string',
					'minLength' => 3,
					'maxLength' => 3,
				),
				'customer_id'          => $int_id,
				'customer_note'        => array( 'type' => 'string' ),
				'billing'              => $person,
				'shipping'             => $person,
				'payment_method'       => array( 'type' => 'string' ),
				'payment_method_title' => array( 'type' => 'string' ),
				'transaction_id'       => array( 'type' => 'string' ),
				'set_paid'             => array( 'type' => 'boolean' ),
				'line_items'           => array(
					'type'  => 'array',
					'items' => $line_item,
				),
				'shipping_lines'       => array(
					'type'  => 'array',
					'items' => $money_item,
				),
				'fee_lines'            => array(
					'type'  => 'array',
					'items' => $money_item,
				),
				'coupon_lines'         => array(
					'type'  => 'array',
					'items' => $money_item,
				),
				'meta_data'            => array(
					'type'  => 'array',
					'items' => array(
						'type'                 => 'object',
						'required'             => array( 'key' ),
						'additionalProperties' => false,
						'properties'           => array(
							'key'   => array( 'type' => 'string' ),
							'value' => array( 'type' => array( 'string', 'integer', 'number', 'boolean' ) ),
						),
					),
				),
			),
		);

		return array(
			'getProducts'      => $read_query,
			'getProduct'       => $read_query,
			'getOrders'        => $read_query,
			'getCustomer'      => $read_query,
			'createOrder'      => $order_write,
			'updateOrder'      => $order_write,
			'customerLogin'    => array(
				'type'                 => 'object',
				'required'             => array( 'username_or_email', 'password' ),
				'additionalProperties' => false,
				'properties'           => array(
					'username_or_email' => array(
						'type'      => 'string',
						'minLength' => 1,
					),
					'password'          => array(
						'type'      => 'string',
						'minLength' => 1,
					),
				),
			),
			'customerRegister' => array(
				'type'                 => 'object',
				'required'             => array( 'email', 'password' ),
				'additionalProperties' => false,
				'properties'           => array(
					'email'    => array(
						'type'      => 'string',
						'minLength' => 3,
					),
					'password' => array(
						'type'      => 'string',
						'minLength' => 12,
					),
					'username' => array( 'type' => 'string' ),
				),
			),
			'refreshToken'     => array(
				'type'                 => 'object',
				'required'             => array( 'refresh_token' ),
				'additionalProperties' => false,
				'properties'           => array(
					'refresh_token' => array(
						'type'      => 'string',
						'minLength' => 1,
					),
				),
			),
			'customerLogout'   => array(
				'type'                 => 'object',
				'additionalProperties' => false,
				'properties'           => array(
					'refresh_token' => array( 'type' => 'string' ),
				),
			),
		);
	}
}
