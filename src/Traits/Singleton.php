<?php
/**
 * Trait Singleton
 *
 * Provides a strict Singleton implementation that can be used by any class
 * within the WooSecureProxy plugin. Ensures only one instance of the class
 * exists in memory at any time and prevents cloning or unserializing.
 *
 * @package WooSecureProxy\Traits
 * @since   1.0.0
 */
namespace WooSecureProxy\Traits;

trait Singleton
{
    /**
     * The single instance of the class.
     *
     * @var static|null
     */
    private static $instance = null;

    /**
     * Returns the singleton instance of the class.
     *
     * Creates the instance on first call if it doesn't already exist.
     *
     * @return static The single instance of the class.
     * @since  1.0.0
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Protected constructor to prevent direct instantiation from outside.
     *
     * Classes using this trait should not be instantiated directly.
     *
     * @since 1.0.0
     */
    private function __construct()
    {
    }

    /**
     * Prevents cloning of the instance.
     *
     * @return void
     * @since  1.0.0
     */
    private function __clone()
    {
    }

    /**
     * Prevents unserializing of the instance.
     *
     * @throws \Exception Always throws an exception to block unserialization.
     * @since  1.0.0
     */
    public function __wakeup()
    {
        throw new \Exception("Cannot unserialize singleton");
    }
}
