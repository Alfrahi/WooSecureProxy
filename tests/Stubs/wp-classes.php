<?php
/**
 * Minimal WordPress/WooCommerce class stubs for unit & characterization tests.
 * Only the members actually used by src/ code are implemented.
 */

declare(strict_types=1);

if (!class_exists('WP_REST_Request')) {
    class WP_REST_Request
    {
        /** @var array<string, string> */
        private array $headers = array();

        private string $body;

        public function __construct(string $body = '')
        {
            $this->body = $body;
        }

        public function set_header(string $name, string $value): void
        {
            $this->headers[strtolower($name)] = $value;
        }

        public function get_header(string $name): string
        {
            return $this->headers[strtolower($name)] ?? '';
        }

        public function get_body(): string
        {
            return $this->body;
        }
    }
}

if (!class_exists('WP_REST_Response')) {
    class WP_REST_Response
    {
        /** @var mixed */
        private $data;

        private int $status;

        /** @var array<string, string> */
        private array $headers = array();

        /**
         * @param mixed $data
         */
        public function __construct($data = null, int $status = 200, array $headers = array())
        {
            $this->data    = $data;
            $this->status  = $status;
            $this->headers = $headers;
        }

        /** @return mixed */
        public function get_data()
        {
            return $this->data;
        }

        public function get_status(): int
        {
            return $this->status;
        }

        /** @return array<string, string> */
        public function get_headers(): array
        {
            return $this->headers;
        }

        public function header(string $key, string $value, bool $replace = true): void
        {
            if ($replace || !isset($this->headers[$key])) {
                $this->headers[$key] = $value;
            }
        }
    }
}

if (!class_exists('WC_Customer')) {
    class WC_Customer
    {
        private int $id;

        public function __construct(int $id = 0)
        {
            $this->id = $id;
        }

        public function get_id(): int
        {
            return $this->id;
        }
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        private string $message;

        public function __construct(string $code = '', string $message = '')
        {
            $this->message = $message;
        }

        public function get_error_message(): string
        {
            return $this->message;
        }
    }
}
