<?php
/**
 * Admin Settings Page handler.
 *
 * Registers the WooSecureProxy settings page under the WordPress Settings menu,
 * handles registration of options, sanitization callbacks, field rendering,
 * and enqueues the CodeMirror editor for JSON fields.
 *
 * @package WooSecureProxy\Admin
 * @since   1.0.0
 */

declare(strict_types=1);

namespace WooSecureProxy\Admin;

class SettingsPage {

	/**
	 * Sets up admin hooks for menu, settings registration, and asset enqueuing.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Adds the WooSecureProxy settings page to the WordPress Settings menu.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function add_menu(): void {
		add_options_page(
			__( 'WooSecureProxy', 'woo-secure-proxy' ),
			__( 'WooSecureProxy', 'woo-secure-proxy' ),
			'manage_options',
			'woo-secure-proxy',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Enqueues CodeMirror editor for JSON fields on the settings page.
	 *
	 * Initializes wp.codeEditor for both allowed tokens and custom rate limits fields.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 * @since  1.0.0
	 */
	public function enqueue_assets( string $hook ): void {
		if ( 'settings_page_woo-secure-proxy' !== $hook ) {
			return;
		}

		$cm_settings = wp_enqueue_code_editor( array( 'type' => 'application/json' ) );
		if ( $cm_settings === false ) {
			return;
		}

		wp_add_inline_script(
			'code-editor',
			'wp.domReady(function () {
            const settings = ' . wp_json_encode( $cm_settings ) . ';
            const rateLimitSettings = ' . wp_json_encode(
				array_merge(
					$cm_settings,
					array( 'codemirror' => array_merge( $cm_settings['codemirror'], array( 'lineNumbers' => true ) ) )
				)
			) . ';
        if (document.getElementById("wsp_allowed_tokens_json")) {
            wp.codeEditor.initialize($("#wsp_allowed_tokens_json"), settings);
    }
    if (document.getElementById("wsp_rate_limits_json")) {
        wp.codeEditor.initialize($("#wsp_rate_limits_json"), rateLimitSettings);
    }
    });'
		);
	}

	/**
	 * Registers settings, sections, and fields for the plugin options.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function register_settings(): void {
		register_setting(
			'wsp_options_group',
			'wsp_allowed_tokens_json',
			array( $this, 'sanitize_tokens' )
		);

		register_setting(
			'wsp_options_group',
			'wsp_rate_limits_json',
			array( $this, 'sanitize_rate_limits' )
		);

		add_settings_section(
			'wsp_main_section',
			'',
			null,
			'woo-secure-proxy'
		);

		add_settings_field(
			'wsp_allowed_tokens_json',
			__( 'Allowed App Tokens', 'woo-secure-proxy' ),
			array( $this, 'field_tokens' ),
			'woo-secure-proxy',
			'wsp_main_section'
		);

		add_settings_field(
			'wsp_rate_limits_json',
			__( 'Rate Limits (JSON)', 'woo-secure-proxy' ),
			array( $this, 'field_rate_limits' ),
			'woo-secure-proxy',
			'wsp_main_section'
		);
	}

	/**
	 * Sanitizes and validates the allowed app tokens JSON input.
	 *
	 * Ensures input is a non-empty JSON array of strings, limits to 100 tokens,
	 * and prevents complete removal of all tokens.
	 *
	 * @param mixed $input Raw input from the settings field.
	 * @return string Sanitized and encoded JSON string.
	 * @since  1.0.0
	 */
	public function sanitize_tokens( $input ): string {
		if ( ! is_string( $input ) ) {
			$input = '';
		}

		$decoded = json_decode( $input, true );
		if ( ! is_array( $decoded ) || empty( $decoded ) ) {
			add_settings_error(
				'wsp_allowed_tokens_json',
				'tokens_error',
				__( 'Invalid tokens format. Must be non-empty JSON array of strings.', 'woo-secure-proxy' ),
				'error'
			);
			return get_option( 'wsp_allowed_tokens_json', '["mobile-v2","app-v3"]' );
		}

		$tokens = array_unique( array_filter( array_map( 'strval', $decoded ) ) );
		if ( empty( $tokens ) ) {
			add_settings_error(
				'wsp_allowed_tokens_json',
				'tokens_empty',
				__( 'You cannot remove all tokens — this would lock out all apps. Add at least one.', 'woo-secure-proxy' ),
				'error'
			);
			return get_option( 'wsp_allowed_tokens_json', '["mobile-v2","app-v3"]' );
		}

		return wp_json_encode( array_values( array_slice( $tokens, 0, 100 ) ) );
	}

	/**
	 * Sanitizes and validates custom rate limits JSON configuration.
	 *
	 * Ensures proper structure with positive numeric values for ip, app, and win.
	 *
	 * @param mixed $input Raw input from the settings field.
	 * @return string Sanitized JSON string or empty if invalid.
	 * @since  1.0.0
	 */
	public function sanitize_rate_limits( $input ): string {
		if ( ! is_string( $input ) || trim( $input ) === '' ) {
			return '';
		}

		$decoded = json_decode( $input, true );
		if ( ! is_array( $decoded ) ) {
			add_settings_error(
				'wsp_rate_limits_json',
				'rl_error',
				__( 'Invalid rate limits JSON. Must be a JSON object.', 'woo-secure-proxy' ),
				'error'
			);
			return get_option( 'wsp_rate_limits_json', '' );
		}

		$valid = true;
		foreach ( $decoded as $action => $limits ) {
			if ( ! is_array( $limits ) || ! isset( $limits['ip'], $limits['app'], $limits['win'] ) ) {
				$valid = false;
				break;
			}
			if ( ! is_numeric( $limits['win'] ) || $limits['win'] <= 0 || $limits['ip'] <= 0 || $limits['app'] <= 0 ) {
				$valid = false;
				break;
			}
		}

		if ( ! $valid ) {
			add_settings_error(
				'wsp_rate_limits_json',
				'rl_error',
				__( 'Rate limit values must be positive numbers and include ip, app, and win.', 'woo-secure-proxy' ),
				'error'
			);
			return get_option( 'wsp_rate_limits_json', '' );
		}

		return wp_json_encode( $decoded );
	}

	/**
	 * Renders the "Allowed App Tokens" textarea field.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function field_tokens(): void {
		$value = get_option( 'wsp_allowed_tokens_json', '["mobile-v2","app-v3"]' );
		?>
		<textarea name="wsp_allowed_tokens_json" id="wsp_allowed_tokens_json" rows="6" class="large-text code">
		<?php
		echo esc_textarea( $value );
		?>
		</textarea>
		<p class="description">
		<?php esc_html_e( 'JSON array of allowed X-App-Token values. Example: ["mobile-v2", "app-v3"]', 'woo-secure-proxy' ); ?>
		<br><strong><?php esc_html_e( 'You must have at least one token — empty list is not allowed.', 'woo-secure-proxy' ); ?></strong>
		</p>
		<?php
	}

	/**
	 * Renders the "Rate Limits (JSON)" textarea field with documentation link.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function field_rate_limits(): void {
		$value = get_option( 'wsp_rate_limits_json', '' );
		?>
		<textarea name="wsp_rate_limits_json" id="wsp_rate_limits_json" rows="18" class="large-text code">
		<?php
		echo esc_textarea( $value );
		?>
		</textarea>
		<p class="description">
		<?php esc_html_e( 'Advanced: Custom rate limits per action. Leave empty for safe defaults.', 'woo-secure-proxy' ); ?>
		<br><a href="https://github.com/Alfrahi/woosecureproxy#rate-limiting-configuration"><?php esc_html_e( 'Full documentation', 'woo-secure-proxy' ); ?></a>
		</p>
		<?php
	}

	/**
	 * Renders the full settings page.
	 *
	 * Includes form, fields, and additional help content from the view template.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'woo-secure-proxy' ) );
		}
		?>
		<div class="wrap">
		<h1><?php esc_html_e( 'WooSecureProxy Settings', 'woo-secure-proxy' ); ?></h1>
		<form method="post" action="options.php">
		<?php
		settings_fields( 'wsp_options_group' );
		do_settings_sections( 'woo-secure-proxy' );
		submit_button( __( 'Save Settings', 'woo-secure-proxy' ) );
		?>
		</form>
		<div style="margin-top: 40px;">
		<?php require WSP_PATH . 'src/Admin/views/settings-page.php'; ?>
		</div>
		</div>
		<?php
	}
}
