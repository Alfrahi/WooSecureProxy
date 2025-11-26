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

if (! defined('ABSPATH')) {
    exit; // Security check – prevent direct access.
}
?>
<h2><?php esc_html_e('Security Status', 'woo-secure-proxy'); ?></h2>

<table class="form-table" role="presentation">
<tr>
<th scope="row"><?php esc_html_e('HMAC Secret (PROXY_SECRET)', 'woo-secure-proxy'); ?></th>
<td>
<code>
<?php if (defined('PROXY_SECRET') && strlen((string) PROXY_SECRET) >= 32) : ?>
<span style="color:green; font-weight:bold;">
<?php esc_html_e('Set', 'woo-secure-proxy'); ?>
(<?php echo esc_html(strlen((string) PROXY_SECRET)); ?> chars)
</span>
<?php else : ?>
<span style="color:red; font-weight:bold;">
<?php esc_html_e('Not defined or too weak!', 'woo-secure-proxy'); ?>
</span>
<p class="description" style="color:red; margin:8px 0 0;">
<?php esc_html_e('The plugin is completely disabled until a strong PROXY_SECRET is defined in wp-config.php.', 'woo-secure-proxy'); ?>
</p>
<?php endif; ?>
</code>
</td>
</tr>

<tr>
<th scope="row"><?php esc_html_e('Internal WooCommerce Auth', 'woo-secure-proxy'); ?></th>
<td>
<?php
// Check if manual WooCommerce consumer key/secret are properly defined
$has_keys = defined('WC_CONSUMER_KEY') && defined('WC_CONSUMER_SECRET')
&& trim(WC_CONSUMER_KEY) !== ''
&& trim((string)WC_CONSUMER_SECRET) !== ''
&& strlen((string)WC_CONSUMER_SECRET) >= 32;

if ($has_keys) :
    ?>
    <span style="color:green; font-weight:bold;">
    <?php esc_html_e('Active (Manual Keys)', 'woo-secure-proxy'); ?>
    </span>
    <?php else : ?>
    <span style="color:red; font-weight:bold;">
    <?php esc_html_e('MISSING – Proxy is DISABLED', 'woo-secure-proxy'); ?>
    </span>
    <p class="description" style="color:red; margin:8px 0 0;">
    <?php esc_html_e('Define WC_CONSUMER_KEY and WC_CONSUMER_SECRET in wp-config.php, or enable Application Passwords for the proxy user.', 'woo-secure-proxy'); ?>
    </p>
    <?php endif; ?>
    </td>
    </tr>
    </table>

    <?php
    // Final warning banner when the entire plugin is disabled due to missing critical constants
    if (defined('WSP_DISABLED') && WSP_DISABLED) :
        ?>
        <div class="notice notice-error inline" style="margin-top: 20px;">
        <p>
        <strong><?php esc_html_e('WooSecureProxy is currently DISABLED.', 'woo-secure-proxy'); ?></strong><br>
        <?php esc_html_e('Fix the issues above and refresh this page.', 'woo-secure-proxy'); ?>
        </p>
        </div>
        <?php endif; ?>
