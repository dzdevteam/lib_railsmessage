<?php
/**
 * This is the Rails Message Decryptor library by DZ Dev Team
 * PHP versions 5
 *
 * LICENSE: GNU GPL v3
 *
 * @package Message
 * @author DZ Dev Team <dev@dzdev.com>
 * @copyright 2014 DZ Dev Team
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3
 */

class InvalidMessageException extends Exception {}

class RailsMessage {
    private $_message;
    private $_base;

    const KEY_ITERATION_NUMBER = 1000;
    const KEY_SIZE = 64;
    const SALT = 'encrypted cookie';

    public function __construct($base, $message = '') {
        $this->_base = $base;
        $this->_message = $message;
    }

    /**
     * Rails encrypted message structure:
     *
     * +--------------------------- URI Encode --------------------------+
     * | +--------------------------- base64 -------+------+-----------+ |
     * | | +---- base64 ----+------+--- base64 ---+ |      |           | |
     * | | | encrypted data | "--" | init. vector | | "--" | signature | |
     * | | +----------------+------+--------------+ |      |           | |
     * | +------------------------------------------+------+-----------+ |
     * +-----------------------------------------------------------------+
     *
     * The default encryption method is AES-256-CBC
     */
    public function decrypt() {
        try {
            // Decode URL encoded message to extract data part
            $message = urldecode($this->_message);
            $parts = explode('--', $message);
            $message = base64_decode($parts[0], true);

            // Extract encrypted data and init vector
            $parts = explode('--', $message);
            $data = base64_decode($parts[0], true);
            $iv = base64_decode($parts[1], true);

            // Now decrypt the message
            $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
            $key = $this->_generateKey();
            $key = substr($key, 0, mcrypt_enc_get_key_size($td));
            $iv = substr($iv, 0, mcrypt_enc_get_iv_size($td));
            if (mcrypt_generic_init($td, $key, $iv) != -1) {
                $decrypted_message = mdecrypt_generic($td, $data);
                /* Clean up */
                mcrypt_generic_deinit($td);
                mcrypt_module_close($td);
            }

            $decrypted_message = trim($decrypted_message, '');
        } catch (Exception $e) {
            throw new InvalidMessageException;
        }

        return $decrypted_message;
    }

    public static function decryptMessage($message, $secret_key_base)
    {
        $message = new self($secret_key_base, $message);

        return $message->decrypt();
    }

    private function _generateKey() {
        return pack('H*', hash_pbkdf2('sha1', $this->_base, self::SALT, self::KEY_ITERATION_NUMBER, self::KEY_SIZE));
    }

    // TODO
    // public function verify() {}
}