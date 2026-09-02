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
use WooSecureProxy\Config;
use WooSecureProxy\Helpers;

class RequestHandler {

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
		'refreshToken'     => array(
			'ep'      => null,
			'methods' => array( 'POST' ),
			'auth'    => 'none',
		),
		'customerLogout'   => array(
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
				// Auth is HMAC-SHA256 verified inside handle_request() (app token,
				// signature, nonce, timestamp). This is open routing, not open access:
				// the permission layer lives in the pipeline, so '__return_true' is correct.
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
		try {
			return $this->dispatch_request( $request );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			// Never leak internals to the client; log full detail server-side.
			$request_id = bin2hex( random_bytes( 8 ) );
			Helpers\Logger::error(
				sprintf(
					'Unhandled exception: %s in %s:%d | REQ %s',
					$e->getMessage(),
					$e->getFile(),
					$e->getLine(),
					$request_id
				)
			);
			return $this->error( 'internal_error', 'Internal server error', 500, $request_id );
		}
	}

	/**
	 * Core request pipeline (wrapped by handle_request's Throwable guard).
	 *
	 * @param WP_REST_Request $request The incoming proxy request.
	 * @return WP_REST_Response Standardized JSON response.
	 */
	private function dispatch_request( WP_REST_Request $request ): WP_REST_Response {
		// Pipeline stages run in order; any guard returning a response halts the chain.
		$ctx = array(
			'request'    => $request,
			'request_id' => bin2hex( random_bytes( 8 ) ),
			'ip'         => Helpers\IpDetector::get_client_ip(),
			'raw_body'   => $request->get_body(),
			'start_time' => microtime( true ),
		);

		foreach (
			array(
				'guard_server_config',
				'guard_size',
				'guard_parse_headers',
				'guard_signature',
				'guard_replay',
				'guard_parse_body',
				'guard_auth_endpoints',
				'guard_allowlist',
				'guard_authn',
				'guard_authz',
				'inject_customer_context',
				'guard_rate_limit',
				'guard_schema',
				'guard_upstream_url',
				'dispatch_upstream',
			) as $stage
		) {
			$result = $this->{$stage}( $ctx );
			if ( $result instanceof WP_REST_Response ) {
				return $result;
			}
		}

		// Unreachable — dispatch_upstream() always returns a response.
		return $this->error( 'internal_error', 'Internal server error', 500, $ctx['request_id'] );
	}

	/**
	 * Pipeline stage: extract and validate required headers.
	 *
	 * @param array<string, mixed> $ctx Pipeline context (headers added by reference).
	 * @return WP_REST_Response|null
	 */
	private function guard_parse_headers( array &$ctx ): ?WP_REST_Response {
		$ctx['headers'] = $this->extract_headers( $ctx['request'] );
		Helpers\Logger::info( "REQ {$ctx['request_id']} | IP: {$ctx['ip']} | App: " . ( $ctx['headers']['app_token'] ?? 'missing' ) );
		return $this->validate_headers( $ctx['headers'], $ctx['request_id'] );
	}

	/**
	 * Pipeline stage: HMAC signature verification.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_signature( array $ctx ): ?WP_REST_Response {
		return $this->verify_signature( $ctx['headers'], $ctx['raw_body'], $ctx['request_id'] );
	}

	/**
	 * Pipeline stage: nonce replay protection.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_replay( array $ctx ): ?WP_REST_Response {
		return $this->check_replay( $ctx['headers']['nonce'], $ctx['request_id'] );
	}

	/**
	 * Pipeline stage: internal WooCommerce auth must be configured.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_server_config( array $ctx ): ?WP_REST_Response {
		if ( ! KeyManager::is_configured() ) {
			return KeyManager::get_disabled_response();
		}
		return null;
	}

	/**
	 * Pipeline stage: enforce body size limit and reject empty payloads.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_size( array $ctx ): ?WP_REST_Response {
		if ( strlen( $ctx['raw_body'] ) > Config::max_body_size() ) {
			return $this->error( 'payload_too_large', 'Request payload exceeds size limit', 413, $ctx['request_id'] );
		}
		if ( trim( $ctx['raw_body'] ) === '' ) {
			return $this->error( 'empty_payload', 'Request body is empty', 400, $ctx['request_id'] );
		}
		return null;
	}

	/**
	 * Pipeline stage: parse JSON body into action/data/method.
	 *
	 * @param array<string, mixed> $ctx Pipeline context (action/data/method/customer_id added by reference).
	 * @return WP_REST_Response|null
	 */
	private function guard_parse_body( array &$ctx ): ?WP_REST_Response {
		try {
			$body = json_decode( $ctx['raw_body'], true, 512, JSON_THROW_ON_ERROR );
		} catch ( \Throwable $e ) {
			return $this->error( 'invalid_json', 'Request body is not valid JSON', 400, $ctx['request_id'] );
		}

		if ( ! is_array( $body ) ) {
			return $this->error( 'invalid_payload', 'Request root must be a JSON object', 400, $ctx['request_id'] );
		}

		$ctx['action'] = isset( $body['action'] ) ? $body['action'] : '';
		$ctx['data']   = isset( $body['data'] ) ? $body['data'] : null;
		$ctx['method'] = strtoupper( isset( $body['method'] ) ? $body['method'] : 'GET' );

		if ( $ctx['action'] === '' ) {
			return $this->error( 'missing_action', 'Request must include "action"', 400, $ctx['request_id'] );
		}

		if ( null === $ctx['data'] || ! is_array( $ctx['data'] ) ) {
			return $this->error( 'invalid_data', '"data" field must be a JSON object', 400, $ctx['request_id'] );
		}

		$ctx['customer_id'] = $this->get_customer_id_from_jwt( $ctx['request'] );

		return null;
	}

	/**
	 * Pipeline stage: built-in auth endpoints (login/register/refresh/logout).
	 * Rate-limited before dispatch to block brute force.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_auth_endpoints( array $ctx ): ?WP_REST_Response {
		if ( ! in_array( $ctx['action'], array( 'customerLogin', 'customerRegister', 'refreshToken', 'customerLogout' ), true ) ) {
			return null;
		}

		$rate_error = $this->rate_limit( $ctx['headers']['app_token'], $ctx['ip'], $ctx['action'], $ctx['request_id'] );
		if ( $rate_error ) {
			return $rate_error;
		}

		return $this->handle_customer_auth( $ctx['action'], $ctx['data'], $ctx['request_id'], $ctx['request'] );
	}

	/**
	 * Pipeline stage: action whitelist and HTTP method check.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_allowlist( array &$ctx ): ?WP_REST_Response {
		$action_config = isset( $this->allowed_actions[ $ctx['action'] ] ) ? $this->allowed_actions[ $ctx['action'] ] : null;
		if ( ! $action_config || ! in_array( $ctx['method'], $action_config['methods'], true ) ) {
			return $this->error( 'action_not_allowed', 'Requested action or method is not permitted', 403, $ctx['request_id'] );
		}
		$ctx['action_config'] = $action_config;
		return null;
	}

	/**
	 * Pipeline stage: authentication — require a valid customer JWT when the
	 * action's auth level demands it.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_authn( array $ctx ): ?WP_REST_Response {
		$auth_mode = $ctx['action_config']['auth'];
		if ( in_array( $auth_mode, array( 'customer', 'customer_self', 'customer_owner' ), true ) && ! $ctx['customer_id'] ) {
			return $this->error( 'unauthenticated', 'Login required for this action', 401, $ctx['request_id'] );
		}
		return null;
	}

	/**
	 * Pipeline stage: authorization — self-access and order-ownership checks.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_authz( array $ctx ): ?WP_REST_Response {
		$auth_mode = $ctx['action_config']['auth'];

		if ( 'customer_self' === $auth_mode ) {
			$requested_id = isset( $ctx['data']['id'] ) ? $ctx['data']['id'] : 0;
			if ( (int) $requested_id !== $ctx['customer_id'] ) {
				return $this->error( 'forbidden', 'You can only access your own customer record', 403, $ctx['request_id'] );
			}
		}

		if ( 'customer_owner' === $auth_mode ) {
			$order_id = isset( $ctx['data']['id'] ) ? $ctx['data']['id'] : 0;
			$order    = wc_get_order( $order_id );

			if ( ! $order || $order->get_customer_id() !== $ctx['customer_id'] ) {
				return $this->error( 'forbidden', 'You can only modify your own orders', 403, $ctx['request_id'] );
			}
		}

		return null;
	}

	/**
	 * Pipeline stage: inject customer context into data for logged-in requests.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function inject_customer_context( array &$ctx ): ?WP_REST_Response {
		if ( 'createOrder' === $ctx['action'] && $ctx['customer_id'] ) {
			$ctx['data']['customer_id'] = $ctx['customer_id'];
		}
		if ( 'getOrders' === $ctx['action'] && $ctx['customer_id'] ) {
			$ctx['data']['customer'] = $ctx['customer_id'];
		}
		return null;
	}

	/**
	 * Pipeline stage: per-action, per-IP and per-app rate limits.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_rate_limit( array $ctx ): ?WP_REST_Response {
		return $this->rate_limit( $ctx['headers']['app_token'], $ctx['ip'], $ctx['action'], $ctx['request_id'] );
	}

	/**
	 * Pipeline stage: JSON Schema validation (ready for per-action schemas).
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_schema( array $ctx ): ?WP_REST_Response {
		if ( ! isset( self::JSON_SCHEMAS[ $ctx['action'] ] ) ) {
			return null;
		}

		$validator = new \JsonSchema\Validator();
		$validator->validate( $ctx['data'], (object) self::JSON_SCHEMAS[ $ctx['action'] ] );

		if ( $validator->isValid() ) {
			return null;
		}

		$errors = array_map(
			function ( $e ) {
				return $e['property'] . ': ' . $e['message'];
			},
			$validator->getErrors()
		);
		Helpers\Logger::warning( "Schema violation | Action: {$ctx['action']} | Errors: " . implode( '; ', $errors ) );
		return $this->error( 'validation_failed', 'Request data does not match expected format', 400, $ctx['request_id'] );
	}

	/**
	 * Pipeline stage: build and validate the upstream WooCommerce URL.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response|null
	 */
	private function guard_upstream_url( array &$ctx ): ?WP_REST_Response {
		$endpoint = $ctx['action_config']['ep'];
		if ( is_string( $endpoint ) && preg_match( '/\(\?P<id>\\\\d\+\)/', $endpoint ) ) {
			$raw_id = $ctx['data']['id'] ?? null;
			if ( ! is_numeric( $raw_id ) || (string) (int) $raw_id !== (string) $raw_id || (int) $raw_id <= 0 ) {
				return $this->error( 'invalid_id', 'A positive integer "id" is required', 400, $ctx['request_id'] );
			}
			$id       = absint( $raw_id );
			$endpoint = preg_replace( '/\(\?P<id>\\\\d\+\)/', (string) $id, $endpoint, 1 );
			unset( $ctx['data']['id'] );
		}

		$wc_url        = rest_url( 'wc/v3/' . $endpoint );
		$upstream_host = wp_parse_url( $wc_url, PHP_URL_HOST );
		$site_host     = wp_parse_url( home_url(), PHP_URL_HOST );

		if ( $upstream_host !== $site_host ) {
			return $this->error( 'invalid_upstream', 'Upstream URL mismatch', 500, $ctx['request_id'] );
		}

		$ctx['wc_url'] = $wc_url;
		return null;
	}

	/**
	 * Pipeline stage: forward to WooCommerce and shape the client response.
	 *
	 * @param array<string, mixed> $ctx Pipeline context.
	 * @return WP_REST_Response
	 */
	private function dispatch_upstream( array $ctx ): WP_REST_Response {
		$data   = $ctx['data'];
		$method = $ctx['method'];
		$wc_url = $ctx['wc_url'];

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

		if ( 'GET' === $method ) {
			// Reject non-scalar values — array_map('sanitize_text_field') would fatal on nested arrays.
			foreach ( $data as $key => $value ) {
				if ( ! is_scalar( $value ) && null !== $value ) {
					return $this->error( 'invalid_data', 'Query parameters must be scalar values', 400, $ctx['request_id'] );
				}
			}
			$wc_url = add_query_arg( array_map( 'sanitize_text_field', $data ), $wc_url );
			if ( strlen( $wc_url ) > 8000 ) {
				return $this->error( 'uri_too_long', 'Request URI exceeds maximum length', 414, $ctx['request_id'] );
			}
		} else {
			$args['body'] = wp_json_encode( $data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR );
		}

		$response = wp_safe_remote_request( $wc_url, $args );

		if ( is_wp_error( $response ) ) {
			Helpers\Logger::error( 'Upstream WC error: ' . sanitize_text_field( $response->get_error_message() ) );
			return $this->error( 'upstream_failure', 'Failed to reach WooCommerce API', 502, $ctx['request_id'] );
		}

		$code      = wp_remote_retrieve_response_code( $response );
		$resp_body = wp_remote_retrieve_body( $response );

		if ( $code >= 500 && ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) ) {
			$resp_body = wp_json_encode( array( 'error' => 'Internal server error' ) );
		}

		$duration = round( ( microtime( true ) - $ctx['start_time'] ) * 1000, 2 );
		$status   = $code < 400 ? 'OK' : 'FAIL';

		Helpers\Logger::info( "{$status} {$code} {$ctx['action']} {$duration}ms | REQ {$ctx['request_id']}" );

		$resp = new WP_REST_Response(
			array(
				'success' => $code < 400,
				'data'    => json_decode( $resp_body, true ) ? json_decode( $resp_body, true ) : $resp_body,
			),
			$code
		);

		$resp->header( 'X-Request-ID', $ctx['request_id'] );
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

		if ( ! ctype_digit( $headers['timestamp'] ) || abs( time() - (int) $headers['timestamp'] ) > Config::timestamp_skew() ) {
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
		$expected       = strtolower( hash_hmac( 'sha256', $string_to_sign, Config::proxy_secret() ) );

		if ( ! hash_equals( $expected, strtolower( $headers['signature'] ) ) ) {
			return $this->error( 'invalid_signature', 'HMAC signature verification failed', 403, $req_id );
		}

		return null;
	}

	/**
	 * Prevents replay attacks by ensuring nonce is used only once within TTL.
	 *
	 * Uses NonceStore for atomic check-and-set — either the persistent
	 * object cache, or the dedicated DB table in degraded mode.
	 *
	 * @param string $nonce  Client-provided nonce.
	 * @param string $req_id Request ID.
	 * @return WP_REST_Response|null
	 */
	private function check_replay( string $nonce, string $req_id ): ?WP_REST_Response {
		if ( ! Helpers\NonceStore::claim( $nonce, Config::nonce_ttl() ) ) {
			return $this->error( 'replay_attack', 'Nonce replay detected', 403, $req_id );
		}

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
				if ( ! headers_sent() ) {
					header( 'Retry-After: ' . $win );
				}
				return $this->error( 'rate_limit_exceeded', 'Too many requests', 429, $req_id );
			}

			if ( defined( 'WP_DEBUG' ) && WP_DEBUG && ! headers_sent() ) {
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
	 * Handles customerLogin, customerRegister, refreshToken and customerLogout actions.
	 *
	 * @param string               $action     Action name.
	 * @param array<string, mixed> $data       Request data.
	 * @param string               $request_id Request ID.
	 * @param WP_REST_Request|null $request    Original request (needed for JWT header on logout).
	 * @return WP_REST_Response
	 */
	private function handle_customer_auth( string $action, array $data, string $request_id, ?WP_REST_Request $request = null ): WP_REST_Response {
		if ( $action === 'customerLogin' ) {
			$identifier = Helpers\LoginThrottle::normalize( $data['username_or_email'] ?? '' );

			if ( Helpers\LoginThrottle::is_locked_out( $identifier ) ) {
				return $this->error( 'account_locked', 'Too many failed login attempts. Please try again later.', 423, $request_id );
			}

			$user = wp_authenticate( $data['username_or_email'] ?? '', $data['password'] ?? '' );

			if ( is_wp_error( $user ) ) {
				Helpers\LoginThrottle::record_failure( $identifier );
				return $this->error( 'invalid_credentials', 'Invalid email or password', 401, $request_id );
			}

			$wc_customer = new \WC_Customer( $user->ID );
			if ( ! $wc_customer->get_id() ) {
				return $this->error( 'not_customer', 'User is not a WooCommerce customer', 403, $request_id );
			}

			Helpers\LoginThrottle::clear( $identifier );

			$customer_id = $wc_customer->get_id();
			return new WP_REST_Response(
				array(
					'success'       => true,
					'jwt'           => \WooSecureProxy\Helpers\JwtHelper::issue( $customer_id ),
					'refresh_token' => \WooSecureProxy\Helpers\JwtHelper::issue_refresh( $customer_id ),
					'customer_id'   => $customer_id,
				),
				200
			);
		}

		if ( $action === 'customerRegister' ) {
			$email    = sanitize_email( $data['email'] ?? '' );
			$password = $data['password'] ?? '';
			$username = $data['username'] ?? '';

			if ( ! is_email( $email ) || strlen( $password ) < 12 ) {
				return $this->error( 'invalid_data', 'Valid email and password ≥12 chars required', 400, $request_id );
			}
			if ( strtolower( $password ) === strtolower( (string) $username ) || strtolower( $password ) === strtolower( $email ) ) {
				return $this->error( 'weak_password', 'Password must not match username or email', 400, $request_id );
			}
			if ( email_exists( $email ) ) {
				return $this->error( 'email_exists', 'Email already registered', 409, $request_id );
			}
			$user_id = wc_create_new_customer( $email, '', $password );
			if ( is_wp_error( $user_id ) ) {
				return $this->error( 'registration_failed', $user_id->get_error_message(), 400, $request_id );
			}
			return new WP_REST_Response(
				array(
					'success'       => true,
					'jwt'           => \WooSecureProxy\Helpers\JwtHelper::issue( $user_id ),
					'refresh_token' => \WooSecureProxy\Helpers\JwtHelper::issue_refresh( $user_id ),
					'customer_id'   => $user_id,
				),
				201
			);
		}

		if ( $action === 'refreshToken' ) {
			$refresh_token = isset( $data['refresh_token'] ) && is_string( $data['refresh_token'] ) ? $data['refresh_token'] : '';
			$new_jwt       = $refresh_token !== '' ? \WooSecureProxy\Helpers\JwtHelper::refresh( $refresh_token ) : null;
			if ( null === $new_jwt ) {
				return $this->error( 'invalid_refresh_token', 'Refresh token is invalid or expired', 401, $request_id );
			}
			return new WP_REST_Response(
				array(
					'success' => true,
					'jwt'     => $new_jwt,
				),
				200
			);
		}

		if ( $action === 'customerLogout' ) {
			$jwt = $request ? $request->get_header( 'x-customer-jwt' ) : '';
			if ( is_string( $jwt ) && $jwt !== '' ) {
				\WooSecureProxy\Helpers\JwtHelper::revoke( $jwt );
			}
			$refresh_token = isset( $data['refresh_token'] ) && is_string( $data['refresh_token'] ) ? $data['refresh_token'] : '';
			if ( $refresh_token !== '' ) {
				\WooSecureProxy\Helpers\JwtHelper::revoke( $refresh_token );
			}
			return new WP_REST_Response(
				array( 'success' => true ),
				200
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
		return Config::allowed_tokens();
	}

	/**
	 * Loads rate limit configuration – merges custom settings with defaults.
	 *
	 * @return array
	 */
	private function get_rate_limits(): array {
		return Config::rate_limits();
	}
}
