<?php
/**
 * Main plugin class.
 *
 * Central entry point and orchestrator for the WooSecureProxy plugin.
 * Implemented as a singleton to ensure only one instance exists and to provide
 * global access via WooSecureProxy::instance().
 *
 * Responsibilities:
 * - Bootstrap admin settings page (only in admin context)
 * - Register the secure proxy REST routes
 * - Handle activation/deactivation tasks (flush rewrite rules)
 *
 * @package WooSecureProxy
 * @since   1.0.0
 */
namespace WooSecureProxy;

final class WooSecureProxy
{
    use Traits\Singleton;

    /**
     * Private constructor.
     *
     * Sets up the primary initialization hook. Direct instantiation is prevented
     * by the Singleton trait.
     *
     * @return void
     * @since  1.0.0
     */
    private function __construct()
    {
        add_action('init', [ $this, 'init' ]);
    }

    /**
     * Initializes the plugin components.
     *
     * - Loads the admin settings page when in the WordPress admin area.
     * - Registers the secure proxy REST API routes.
     *
     * @return void
     * @since  1.0.0
     */
    public function init(): void
    {
        if (is_admin()) {
            new Admin\SettingsPage();
        }

        add_action('rest_api_init', [ new Proxy\RequestHandler(), 'register_routes' ]);
    }

    /**
     * Runs on plugin activation.
     *
     * Flushes rewrite rules to ensure REST API endpoints are immediately available.
     *
     * @return void
     * @since  1.0.0
     */
    public static function activate(): void
    {
        flush_rewrite_rules();
    }

    /**
     * Runs on plugin deactivation.
     *
     * Flushes rewrite rules to clean up any custom permalinks/endpoint registrations.
     *
     * @return void
     * @since  1.0.0
     */
    public static function deactivate(): void
    {
        flush_rewrite_rules();
    }
}
