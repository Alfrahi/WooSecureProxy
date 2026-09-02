<?php
/**
 * Admin settings page – additional help / status view.
 *
 * Displays real-time security status for the most critical configuration items:
 * - PROXY_SECRET strength
 * - Internal WooCommerce authentication (manual keys)
 * - Overall plugin enable/disable state
 *
 * Included from SettingsPage::render_page() after the main form.
 *
 * @package WooSecureProxy\Admin\views
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Security check – prevent direct access.
}
?>
<h2><?php esc_html_e( 'Security Status', 'woo-secure-proxy' ); ?></h2>

<table class="form-table" role="presentation">
<tr>
<th scope="row"><?php esc_html_e( 'HMAC Secret (PROXY_SECRET)', 'woo-secure-proxy' ); ?></th>
<td>
<code>
<?php if ( \WooSecureProxy\Config::proxy_secret() !== '' ) : ?>
<span style="color:green; font-weight:bold;">
	<?php esc_html_e( 'Set', 'woo-secure-proxy' ); ?>
(<?php echo esc_html( strlen( \WooSecureProxy\Config::proxy_secret() ) ); ?> chars)
</span>
<?php else : ?>
<span style="color:red; font-weight:bold;">
	<?php esc_html_e( 'Not defined or too weak!', 'woo-secure-proxy' ); ?>
</span>
<p class="description" style="color:red; margin:8px 0 0;">
	<?php esc_html_e( 'The plugin is completely disabled until a strong PROXY_SECRET is defined in wp-config.php.', 'woo-secure-proxy' ); ?>
	<?php
	printf(
		/* translators: %s: wp-config.php definition example. */
		esc_html__( 'Generate one in a WP-CLI or admin context with wp_generate_password( 64, true, true ) — or any CSPRNG — then define it yourself: %s. Never paste a secret shown in this admin page into an app; it must be provisioned out-of-band.', 'woo-secure-proxy' ),
		'<code>define( &quot;PROXY_SECRET&quot;, &quot;&lt;64+ random chars&gt;&quot; );</code>'
	);
	?>
</p>
<?php endif; ?>
</code>
</td>
</tr>

<tr>
<th scope="row"><?php esc_html_e( 'Internal WooCommerce Auth', 'woo-secure-proxy' ); ?></th>
<td>
<?php
$wsp_has_keys = \WooSecureProxy\Config::has_wc_credentials();

if ( $wsp_has_keys ) :
	?>
	<span style="color:green; font-weight:bold;">
	<?php esc_html_e( 'Active (Manual Keys)', 'woo-secure-proxy' ); ?>
	</span>
	<?php else : ?>
	<span style="color:red; font-weight:bold;">
		<?php esc_html_e( 'MISSING – Proxy is DISABLED', 'woo-secure-proxy' ); ?>
	</span>
	<p class="description" style="color:red; margin:8px 0 0;">
		<?php esc_html_e( 'Define WC_CONSUMER_KEY and WC_CONSUMER_SECRET in wp-config.php, or enable Application Passwords for the proxy user.', 'woo-secure-proxy' ); ?>
	</p>
	<?php endif; ?>
	</td>
	</tr>
	</table>

	<h2><?php esc_html_e( 'Request Counters (last 48 h)', 'woo-secure-proxy' ); ?></h2>
	<?php
	$wsp_metrics = \WooSecureProxy\Helpers\Metrics::summary();
	if ( empty( $wsp_metrics ) ) :
		?>
		<p><?php esc_html_e( 'No proxied requests recorded yet.', 'woo-secure-proxy' ); ?></p>
	<?php else : ?>
		<table class="widefat striped" style="max-width: 640px;">
		<thead>
		<tr>
		<th scope="col"><?php esc_html_e( 'Day (UTC)', 'woo-secure-proxy' ); ?></th>
		<th scope="col"><?php esc_html_e( 'Action', 'woo-secure-proxy' ); ?></th>
		<th scope="col"><?php esc_html_e( '2xx', 'woo-secure-proxy' ); ?></th>
		<th scope="col"><?php esc_html_e( '4xx', 'woo-secure-proxy' ); ?></th>
		<th scope="col"><?php esc_html_e( '5xx', 'woo-secure-proxy' ); ?></th>
		</tr>
		</thead>
		<tbody>
		<?php foreach ( $wsp_metrics as $wsp_day => $wsp_actions ) : ?>
			<?php foreach ( $wsp_actions as $wsp_action => $wsp_buckets ) : ?>
				<tr>
				<td><?php echo esc_html( $wsp_day ); ?></td>
				<td><code><?php echo esc_html( $wsp_action ); ?></code></td>
				<td><?php echo esc_html( (string) ( $wsp_buckets['2xx'] ?? 0 ) ); ?></td>
				<td><?php echo esc_html( (string) ( $wsp_buckets['4xx'] ?? 0 ) ); ?></td>
				<td><?php echo esc_html( (string) ( $wsp_buckets['5xx'] ?? 0 ) ); ?></td>
				</tr>
			<?php endforeach; ?>
		<?php endforeach; ?>
		</tbody>
		</table>
	<?php endif; ?>

	<?php
	// Final warning banner when the entire plugin is disabled due to missing critical constants.
	if ( defined( 'WSP_DISABLED' ) && WSP_DISABLED ) :
		?>
		<div class="notice notice-error inline" style="margin-top: 20px;">
		<p>
		<strong><?php esc_html_e( 'WooSecureProxy is currently DISABLED.', 'woo-secure-proxy' ); ?></strong><br>
		<?php esc_html_e( 'Fix the issues above and refresh this page.', 'woo-secure-proxy' ); ?>
		</p>
		</div>
		<?php endif; ?>
