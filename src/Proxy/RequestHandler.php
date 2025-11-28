<?php
/**
 * Core proxy request handler.
 *
 * This is the heart of WooSecureProxy. It receives a single POST request to
 * /wp-json/woosecureproxy/v3/proxy containing a signed JSON payload, validates
 * authentication, authorization, rate limits, replay attacks, JSON schema (when defined),
 * and forwards the request to the internal WooCommerce REST API using secure credentials.
 *
 * Security features implemented:
 * - HMAC-SHA256 signature verification
 * - Replay attack protection (nonce + timestamp)
 * - Per-endpoint and per-app/IP rate limiting
 * - Request size limits
 * - Strict JSON payload validation
 * - Customer JWT authentication with scope and ownership checks
 *
 * @package WooSecureProxy\Proxy
 * @since   1.0.0
 */

declare(strict_types=1);

namespace WooSecureProxy\Proxy;

use WP_REST_Request;
use WP_REST_Response;
use WooSecureProxy\Auth\KeyManager;
use WooSecureProxy\Helpers;

class RequestHandler {

	/** Maximum allowed request body size (defaults to PROXY_MAX_BODY_SIZE constant) */
	private const MAX_BODY_SIZE = PROXY_MAX_BODY_SIZE;

	/**
	 * List of allowed proxy actions and their corresponding WooCommerce REST endpoints.
	 *
	 * @var array<string, array>
	 */
	private array $allowed_actions = array(
		'getProducts'      => array(
			'ep'      => 'products',
			'methods' => array( 'GET' ),
			'auth'    => 'none',
		),
		'getProduct'       => array(
			'ep'      => 'products/(?P<id>\d+)',
			'methods' => array( 'GET' ),
			'auth'    => 'none',
		),
		'getOrders'        => array(
			'ep'      => 'orders',
			'methods' => array( 'GET' ),
			'auth'    => 'customer',
		),
		'getCustomer'      => array(
			'ep'      => 'customers/(?P<id>\d+)',
			'methods' => array( 'GET' ),
			'auth'    => 'customer_self',
		),
		'updateOrder'      => array(
			'ep'      => 'orders/(?P<id>\d+)',
			'methods' => array( 'PUT', 'PATCH' ),
			'auth'    => 'customer_owner',
		),
		'createOrder'      => array(
			'ep'      => 'orders',
			'methods' => array( 'POST' ),
			'auth'    => 'optional',
		),
		'customerLogin'    => array(
			'ep'      => null,
			'methods' => array( 'POST' ),
			'auth'    => 'none',
		),
		'customerRegister' => array(
			'ep'      => null,
			'methods' => array( 'POST' ),
			'auth'    => 'none',
		),
	);

	/** Runtime-loaded rate limit configuration */
	private array $rate_limits = array();

	/** Runtime-loaded list of allowed X-App-Token values */
	private array $allowed_tokens = array();

	/** Placeholder for future JSON Schema validation per action */
	private const JSON_SCHEMAS = array();

	/**
	 * Constructor – loads current allowed tokens and rate limits from options.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {
		$this->allowed_tokens = $this->get_allowed_tokens();
		$this->rate_limits    = $this->get_rate_limits();
	}

	/**
	 * Registers the single proxy endpoint: POST /wp-json/woosecureproxy/v3/proxy
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function register_routes(): void {
		register_rest_route(
			'woosecureproxy/v3',
			'/proxy',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_request' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Main request handler – validates, authenticates, authorizes, and proxies the request.
	 *
	 * @param WP_REST_Request $request The incoming proxy request.
	 * @return WP_REST_Response Standardized JSON response.
	 * @since  1.0.0
	 */
	public function handle_request( WP_REST_Request $request ): WP_REST_Response {
		$start_time = microtime( true );
		$request_id = bin2hex( random_bytes( 8 ) );
		$ip         = Helpers\IpDetector::get_client_ip();
		$raw_body   = $request->get_body();

		// Critical: internal auth must be configured.
		if ( ! KeyManager::is_configured() ) {
			return KeyManager::get_disabled_response();
		}

		// Size & emptiness checks.
		if ( strlen( $raw_body ) > self::MAX_BODY_SIZE ) {
			return $this->error( 'payload_too_large', 'Request payload exceeds size limit', 413, $request_id );
		}
		if ( trim( $raw_body ) === '' ) {
			return $this->error( 'empty_payload', 'Request body is empty', 400, $request_id );
		}

		$headers = $this->extract_headers( $request );
		Helpers\Logger::info( "REQ {$request_id} | IP: {$ip} | App: " . ( $headers['app_token'] ?? 'missing' ) );

		// Header validation.
		$header_error = $this->validate_headers( $headers, $request_id );
		if ( $header_error ) {
			return $header_error;
		}

		// HMAC signature verification.
		$signature_error = $this->verify_signature( $headers, $raw_body, $request_id );
		if ( $signature_error ) {
			return $signature_error;
		}

		// Replay attack protection.
		$replay_error = $this->check_replay( $headers['nonce'], $request_id );
		if ( $replay_error ) {
			return $replay_error;
		}

		// Parse JSON body.
		try {
			$body = json_decode( $raw_body, true, 512, JSON_THROW_ON_ERROR );
		} catch ( \Throwable $e ) {
			return $this->error( 'invalid_json', 'Request body is not valid JSON', 400, $request_id );
		}

		if ( ! is_array( $body ) ) {
			return $this->error( 'invalid_payload', 'Request root must be a JSON object', 400, $request_id );
		}

		$action = isset( $body['action'] ) ? $body['action'] : '';
		$data   = isset( $body['data'] )   ? $body['data']   : null;
		$method = strtoupper( isset( $body['method'] ) ? $body['method'] : 'GET' );

		if ( $action === '' ) {
			return $this->error( 'missing_action', 'Request must include "action"', 400, $request_id );
		}

		if ( $data === null || ! is_array( $data ) ) {
			return $this->error( 'invalid_data', '"data" field must be a JSON object', 400, $request_id );
		}

		// Customer JWT authentication.
		$customer_id = $this->get_customer_id_from_jwt( $request );

		// Special built-in auth endpoints.
		if ( in_array( $action, array( 'customerLogin', 'customerRegister' ), true ) ) {
			return $this->handle_customer_auth( $action, $data, $request_id );
		}

		// Action whitelist & method check.
		$action_config = isset( $this->allowed_actions[ $action ] ) ? $this->allowed_actions[ $action ] : null;
		if ( ! $action_config || ! in_array( $method, $action_config['methods'], true ) ) {
			return $this->error( 'action_not_allowed', 'Requested action or method is not permitted', 403, $request_id );
		}

		$auth_mode = $action_config['auth'];

		// Enforce login when required.
		if ( in_array( $auth_mode, array( 'customer', 'customer_self', 'customer_owner' ), true ) && ! $customer_id ) {
			return $this->error( 'unauthenticated', 'Login required for this action', 401, $request_id );
		}

		// Self-access enforcement.
		if ( $auth_mode === 'customer_self' ) {
			$requested_id = isset( $data['id'] ) ? $data['id'] : 0;
			if ( (int) $requested_id !== $customer_id ) {
				return $this->error( 'forbidden', 'You can only access your own customer record', 403, $request_id );
			}
		}

		// Order ownership enforcement.
		if ( $auth_mode === 'customer_owner' ) {
			$order_id = isset( $data['id'] ) ? $data['id'] : 0;
			$order    = wc_get_order( $order_id );

			if ( ! $order || $order->get_customer_id() !== $customer_id ) {
				return $this->error( 'forbidden', 'You can only modify your own orders', 403, $request_id );
			}
		}

		// Auto-fill customer context.
		if ( $action === 'createOrder' && $customer_id ) {
			$data['customer_id'] = $customer_id;
		}
		if ( $action === 'getOrders' && $customer_id ) {
			$data['customer'] = $customer_id;
		}

		// Rate limiting.
		$rate_error = $this->rate_limit( $headers['app_token'], $ip, $action, $request_id );
		if ( $rate_error ) {
			return $rate_error;
		}

		// JSON Schema validation (stub – ready for future schemas).
		if ( isset( self::JSON_SCHEMAS[ $action ] ) ) {
			$validator = new \JsonSchema\Validator();
			$validator->validate( $data, (object) self::JSON_SCHEMAS[ $action ] );

			if ( ! $validator->isValid() ) {
				$errors = array_map(
					function ( $e ) {
						return $e['property'] . ': ' . $e['message'];
					},
					$validator->getErrors()
				);
				Helpers\Logger::warning( "Schema violation | Action: {$action} | Errors: " . implode( '; ', $errors ) );
				return $this->error( 'validation_failed', 'Request data does not match expected format', 400, $request_id );
			}
		}

		// Build upstream WooCommerce URL.
		$wc_url        = rest_url( 'wc/v3/' . $action_config['ep'] );
		$upstream_host = wp_parse_url( $wc_url, PHP_URL_HOST );
		$site_host     = wp_parse_url( home_url(), PHP_URL_HOST );

		if ( $upstream_host !== $site_host ) {
			return $this->error( 'invalid_upstream', 'Upstream URL mismatch', 500, $request_id );
		}

		// Prepare wp_safe_remote_request arguments.
		$args = array(
			'method'      => $method,
			'timeout'     => 30,
			'headers'     => array_merge(
				KeyManager::get_auth_header(),
				array(
					'Content-Type' => 'application/json',
					'User-Agent'   => 'WooSecureProxy/' . WSP_VERSION,
				)
			),
			'redirection' => 0,
			'sslverify'   => true,
		);

		if ( $method === 'GET' ) {
			$wc_url = add_query_arg( array_map( 'sanitize_text_field', $data ), $wc_url );
			if ( strlen( $wc_url ) > 8000 ) {
				return $this->error( 'uri_too_long', 'Request URI exceeds maximum length', 414, $request_id );
			}
		} else {
			$args['body'] = wp_json_encode( $data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR );
		}

		// Forward request to WooCommerce.
		$response = wp_safe_remote_request( $wc_url, $args );

		if ( is_wp_error( $response ) ) {
			Helpers\Logger::error( 'Upstream WC error: ' . sanitize_text_field( $response->get_error_message() ) );
			return $this->error( 'upstream_failure', 'Failed to reach WooCommerce API', 502, $request_id );
		}

		$code      = wp_remote_retrieve_response_code( $response );
		$resp_body = wp_remote_retrieve_body( $response );

		// Hide internal errors in production.
		if ( $code >= 500 && ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) ) {
			$resp_body = wp_json_encode( array( 'error' => 'Internal server error' ) );
		}

		$duration = round( ( microtime( true ) - $start_time ) * 1000, 2 );
		$status   = $code < 400 ? 'OK' : 'FAIL';

		Helpers\Logger::info( "{$status} {$code} {$action} {$duration}ms | REQ {$request_id}" );

		$resp = new WP_REST_Response(
			array(
				'success' => $code < 400,
				'data'    => json_decode( $resp_body, true ) ? json_decode( $resp_body, true ) : $resp_body,
			),
			$code
		);

		$resp->header( 'X-Request-ID', $request_id );
		$resp->header( 'X-Proxy-Version', WSP_VERSION );
		$resp->header( 'Content-Type', 'application/json; charset=' . get_option( 'blog_charset' ) );

		return $resp;
	}

	/**
	 * Extracts and sanitizes required proxy headers from the request.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return array Normalized headers.
	 */
	private function extract_headers( WP_REST_Request $request ): array {
		$raw = array(
			'app_token' => (string) ( $request->get_header( 'x-app-token' ) ?? '' ),
			'timestamp' => (string) ( $request->get_header( 'x-timestamp' ) ?? '' ),
			'nonce'     => (string) ( $request->get_header( 'x-nonce' ) ?? '' ),
			'signature' => (string) ( $request->get_header( 'x-signature' ) ?? '' ),
		);

		array_walk(
			$raw,
			static function ( &$v ) {
				$v = trim( $v );
				$v = preg_replace( '/[\x00-\x1F\x7F]/u', '', $v );
			}
		);

		$raw['signature'] = strtolower( $raw['signature'] );
		return $raw;
	}

	/**
	 * Validates presence and format of all required proxy headers.
	 *
	 * @param array  $headers   Extracted headers.
	 * @param string $req_id    Request ID for logging.
	 * @return WP_REST_Response|null Error response or null if valid.
	 */
	private function validate_headers( array $headers, string $req_id ): ?WP_REST_Response {
		$required = array( 'app_token', 'timestamp', 'nonce', 'signature' );
		foreach ( $required as $key ) {
			if ( empty( $headers[ $key ] ) ) {
				return $this->error( 'missing_header', 'Missing header: X-' . str_replace( '_', '-', $key ), 400, $req_id );
			}
		}

		if ( ! in_array( $headers['app_token'], $this->allowed_tokens, true ) ) {
			return $this->error( 'invalid_token', 'Invalid or revoked app token', 403, $req_id );
		}

		if ( ! ctype_digit( $headers['timestamp'] ) || abs( time() - (int) $headers['timestamp'] ) > PROXY_TIMESTAMP_SKEW ) {
			return $this->error( 'invalid_timestamp', 'Timestamp outside allowed skew', 403, $req_id );
		}

		if ( ! preg_match( '/^[a-f0-9]{16,}$/i', $headers['nonce'] ) ) {
			return $this->error( 'invalid_nonce', 'Nonce format invalid', 400, $req_id );
		}

		return null;
	}

	/**
	 * Verifies HMAC-SHA256 signature over timestamp + nonce + raw body.
	 *
	 * @param array  $headers   Headers containing signature.
	 * @param string $raw_body  Raw request body.
	 * @param string $req_id    Request ID.
	 * @return WP_REST_Response|null Error or null if valid.
	 */
	private function verify_signature( array $headers, string $raw_body, string $req_id ): ?WP_REST_Response {
		$string_to_sign = $headers['timestamp'] . $headers['nonce'] . $raw_body;
		$expected       = strtolower( hash_hmac( 'sha256', $string_to_sign, PROXY_SECRET ) );

		if ( ! hash_equals( $expected, strtolower( $headers['signature'] ) ) ) {
			return $this->error( 'invalid_signature', 'HMAC signature verification failed', 403, $req_id );
		}

		return null;
	}

	/**
	 * Prevents replay attacks by ensuring nonce is used only once within TTL.
	 *
	 * Uses both object cache and transient as fallback.
	 *
	 * @param string $nonce  Client-provided nonce.
	 * @param string $req_id Request ID.
	 * @return WP_REST_Response|null
	 */
	private function check_replay( string $nonce, string $req_id ): ?WP_REST_Response {
		$key = "wsp_nonce_{$nonce}";

		if ( wp_cache_get( $key, 'wsp_nonces' ) ) {
			return $this->error( 'replay_attack', 'Nonce replay detected', 403, $req_id );
		}

		wp_cache_set( $key, true, 'wsp_nonces', PROXY_NONCE_TTL );

		if ( get_transient( $key ) ) {
			return $this->error( 'replay_attack', 'Nonce replay detected', 403, $req_id );
		}

		set_transient( $key, true, PROXY_NONCE_TTL );
		return null;
	}

	/**
	 * Enforces per-action, per-IP and per-app rate limits.
	 *
	 * @param string $app_token App identifier.
	 * @param string $ip        Client IP.
	 * @param string $action    Requested action.
	 * @param string $req_id    Request ID.
	 * @return WP_REST_Response|null
	 */
	private function rate_limit( string $app_token, string $ip, string $action, string $req_id ): ?WP_REST_Response {
		$action = $action === '' ? 'unknown' : $action;
		$limits = $this->rate_limits[ $action ] ?? $this->rate_limits['default'];

		foreach ( array(
			'ip'  => $ip,
			'app' => $app_token,
		) as $type => $id ) {
			$key   = "wsp_rl_{$action}_{$type}_" . hash( 'sha256', $id );
			$win   = max( 30, min( 86400, (int) ( $limits['win'] ?? 60 ) ) );
			$count = wp_cache_get( $key, 'wsp_rl' );
			if ( false === $count ) {
				$count = 0;
			}
			$new_count = $count + 1;
			wp_cache_set( $key, $new_count, 'wsp_rl', $win );
			$count = $new_count;

			if ( $count > $limits[ $type ] ) {
				header( 'Retry-After: ' . $win );
				return $this->error( 'rate_limit_exceeded', 'Too many requests', 429, $req_id );
			}

			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				header( "X-RateLimit-Remaining-{$type}: " . max( 0, $limits[ $type ] - $count ) );
				header( "X-RateLimit-Limit-{$type}: " . $limits[ $type ] );
				header( "X-RateLimit-Reset-{$type}: " . ( time() + $win ) );
			}
		}

		return null;
	}

	/**
	 * Extracts and validates customer JWT from X-Customer-JWT header.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return int|null Customer ID or null if invalid/missing.
	 */
	private function get_customer_id_from_jwt( WP_REST_Request $request ): ?int {
		$jwt = $request->get_header( 'x-customer-jwt' );
		return \WooSecureProxy\Helpers\JwtHelper::validate( $jwt );
	}

	/**
	 * Handles customerLogin and customerRegister actions.
	 *
	 * @param string $action     Action name.
	 * @param array  $data       Request data.
	 * @param string $request_id Request ID.
	 * @return WP_REST_Response
	 */
	private function handle_customer_auth( string $action, array $data, string $request_id ): WP_REST_Response {
		if ( $action === 'customerLogin' ) {
			$user = wp_authenticate( $data['username_or_email'] ?? '', $data['password'] ?? '' );
			if ( is_wp_error( $user ) ) {
				return $this->error( 'invalid_credentials', 'Invalid email or password', 401, $request_id );
			}
			$wc_customer = new \WC_Customer( $user->ID );
			if ( ! $wc_customer->get_id() ) {
				return $this->error( 'not_customer', 'User is not a WooCommerce customer', 403, $request_id );
			}
			$jwt = \WooSecureProxy\Helpers\JwtHelper::issue( $wc_customer->get_id() );
			return new WP_REST_Response(
				array(
					'success'     => true,
					'jwt'         => $jwt,
					'customer_id' => $wc_customer->get_id(),
				),
				200
			);
		}

		if ( $action === 'customerRegister' ) {
			$email    = sanitize_email( $data['email'] ?? '' );
			$password = $data['password'] ?? '';
			if ( ! is_email( $email ) || strlen( $password ) < 6 ) {
				return $this->error( 'invalid_data', 'Valid email and password ≥6 chars required', 400, $request_id );
			}
			if ( email_exists( $email ) ) {
				return $this->error( 'email_exists', 'Email already registered', 409, $request_id );
			}
			$user_id = wc_create_new_customer( $email, '', $password );
			if ( is_wp_error( $user_id ) ) {
				return $this->error( 'registration_failed', $user_id->get_error_message(), 400, $request_id );
			}
			$jwt = \WooSecureProxy\Helpers\JwtHelper::issue( $user_id );
			return new WP_REST_Response(
				array(
					'success'     => true,
					'jwt'         => $jwt,
					'customer_id' => $user_id,
				),
				201
			);
		}

		return $this->error( 'invalid_action', 'Unknown auth action', 400, $request_id );
	}

	/**
	 * Returns a standardized error response.
	 *
	 * @param string $code       Error code.
	 * @param string $message    Error message.
	 * @param int    $status     HTTP status code.
	 * @param string $request_id Request ID.
	 * @return WP_REST_Response
	 */
	private function error( string $code, string $message, int $status, string $request_id ): WP_REST_Response {
		Helpers\Logger::warning( "ERR {$status} {$code} | {$message} | REQ {$request_id}" );
		$response = new WP_REST_Response(
			array(
				'success' => false,
				'error'   => array(
					'code'    => $code,
					'message' => $message,
				),
			),
			$status
		);
		$response->header( 'X-Request-ID', $request_id );
		$response->header( 'Content-Type', 'application/json' );
		return $response;
	}

	/**
	 * Loads allowed app tokens from database option.
	 *
	 * @return array
	 */
	private function get_allowed_tokens(): array {
		$json   = get_option( 'wsp_allowed_tokens_json', '["mobile-v2","app-v3"]' );
		$tokens = json_decode( $json, true );
		$tokens = is_array( $tokens ) ? array_values( array_unique( array_filter( $tokens ) ) ) : array( 'mobile-v2' );
		return array_slice( $tokens, 0, 50 );
	}

	/**
	 * Loads rate limit configuration – merges custom settings with defaults.
	 *
	 * @return array
	 */
	private function get_rate_limits(): array {
		global $wsp_default_rate_limits;

		$json = get_option( 'wsp_rate_limits_json', '' );

		if ( $json !== '' ) {
			$custom = json_decode( $json, true );

			if ( is_array( $custom ) ) {
				return array_replace_recursive( $wsp_default_rate_limits, $custom );
			}
		}

		return $wsp_default_rate_limits;
	}
}
