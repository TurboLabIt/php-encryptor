<?php
namespace TurboLabIt\Encryptor;

use Random\Engine\Secure;
use Random\Randomizer;


class Encryptor
{
    // authenticated-format marker, appended to the END of the ciphertext; legacy AES-CBC has none
    const VERSION_TAG = "-v2";

    const LEGACY_KEY_HASHING_ALGO   = "sha512";
    const LEGACY_ENCRYPT_ALGO       = "AES256";

    protected string $sodiumKey;
    protected string $legacyKey;
    protected int $legacyIvNumBytes;

    protected array $specialCharMap = [
        "/"     => "__ssym1__",
        "\\"    => "__ssym2__",
    ];


    public function __construct(string $secretKey)
    {
        if( $secretKey === '' ) {
            throw new EncryptionException("Encryptor requires a non-empty secret key");
        }

        // 32-byte secretbox key, derived from the provided secret (BLAKE2b)
        $this->sodiumKey = sodium_crypto_generichash($secretKey, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

        // legacy AES-256-CBC key material (decrypt-only)
        $this->legacyKey        = openssl_digest($secretKey, static::LEGACY_KEY_HASHING_ALGO, true);
        $this->legacyIvNumBytes = openssl_cipher_iv_length(static::LEGACY_ENCRYPT_ALGO);
    }


    /**
     * Returns the secret key stored at $filePath/encryptor/$fileName.key, provisioning it on first use:
     * a 256-bit CSPRNG key written with 0600 permissions. Subsequent calls just read it back.
     *
     * Pass an absolute $filePath (e.g. the project's var dir) so the location never depends on the CWD.
     */
    public static function getSuperSecureKey(string $filePath, string $fileName) : string
    {
        $fullPath = rtrim($filePath, '/') . "/encryptor/" . $fileName . ".key";

        if( !is_file($fullPath) ) {

            $dir = dirname($fullPath);
            if( !is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir) ) {
                throw new EncryptionException("getSuperSecureKey() failure: cannot create directory '$dir'");
            }

            // 256-bit key from the OS CSPRNG
            $key = bin2hex( (new Randomizer(new Secure()))->getBytes(32) );

            // 'x' fails if the file already exists (race with a concurrent generator) → then we just read it
            $handle = @fopen($fullPath, 'xb');
            if( $handle !== false ) {
                chmod($fullPath, 0600);
                fwrite($handle, $key);
                fclose($handle);
            }
        }

        $key = @file_get_contents($fullPath);
        if( !is_string($key) || $key === '' ) {
            throw new EncryptionException("getSuperSecureKey() failure: cannot read key file '$fullPath'");
        }

        return trim($key);
    }


    public function encrypt($data) : string
    {
        $this->preventLeaks();

        if( empty($data) ) {
            return '';
        }

        $txtData = is_array($data) || is_object($data) ? serialize($data) : (string)$data;

        // random nonce, stored alongside the ciphertext+tag
        $nonce      = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipherText = sodium_crypto_secretbox($txtData, $nonce, $this->sodiumKey);

        $base64  = base64_encode($nonce . $cipherText);

        // make it URL-safe (no "/" or "\")
        $urlSafe = str_ireplace(array_keys($this->specialCharMap), $this->specialCharMap, $base64);

        return $urlSafe . static::VERSION_TAG;
    }


    public function decrypt($encodedEncryptedString, bool $unserialize = true, bool $allowLegacy = false)
    {
        $this->preventLeaks();

        if( empty($encodedEncryptedString) ) {
            return $encodedEncryptedString;
        }

        $encodedEncryptedString = (string)$encodedEncryptedString;

        // 🔐 current authenticated format
        if( str_ends_with($encodedEncryptedString, static::VERSION_TAG) ) {
            return $this->decryptAuthenticated($encodedEncryptedString, $unserialize);
        }

        // ⚠️ legacy unauthenticated format (pre-existing ciphertexts only)
        if( !$allowLegacy ) {
            throw new EncryptionException("decrypt() failure: refusing unauthenticated (legacy) ciphertext");
        }

        return $this->decryptLegacy($encodedEncryptedString, $unserialize);
    }


    //<editor-fold defaultstate="collapsed" desc="*** 👷 Internal ***">
    protected function decryptAuthenticated(string $encoded, bool $unserialize)
    {
        $encoded = substr($encoded, 0, -strlen(static::VERSION_TAG));
        $encoded = str_ireplace($this->specialCharMap, array_keys($this->specialCharMap), $encoded);

        $raw = base64_decode($encoded, true);

        $minLength = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
        if( $raw === false || strlen($raw) < $minLength ) {
            throw new EncryptionException("decrypt() failure: malformed input");
        }

        $nonce      = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipherText = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $plainText = sodium_crypto_secretbox_open($cipherText, $nonce, $this->sodiumKey);
        if( $plainText === false ) {
            // authentication failed: tampered ciphertext or wrong key
            throw new EncryptionException("decrypt() failure: authentication check failed");
        }

        return $this->maybeUnserialize($plainText, $unserialize);
    }


    protected function decryptLegacy(string $encoded, bool $unserialize)
    {
        $encoded            = str_ireplace($this->specialCharMap, array_keys($this->specialCharMap), $encoded);
        $encryptedString    = base64_decode($encoded);

        if( strlen($encryptedString) < $this->legacyIvNumBytes ) {
            throw new EncryptionException("decrypt() failure: input is too short");
        }

        $initVector         = substr($encryptedString, 0, $this->legacyIvNumBytes);
        $encryptedString    = substr($encryptedString, $this->legacyIvNumBytes);

        $plainText = openssl_decrypt($encryptedString, static::LEGACY_ENCRYPT_ALGO, $this->legacyKey, OPENSSL_RAW_DATA, $initVector);
        if( $plainText === false ) {
            throw new EncryptionException("decrypt() failure: " . openssl_error_string());
        }

        return $this->maybeUnserialize($plainText, $unserialize);
    }


    protected function maybeUnserialize(string $plainText, bool $unserialize)
    {
        if( !$unserialize ) {
            return $plainText;
        }

        $arrData = @unserialize($plainText);
        if( $arrData === false ) {
            throw new \Exception("decrypt() failure: unable to unserialize");
        }

        return $arrData;
    }


    protected function preventLeaks() : void
    {
        if( empty($this->sodiumKey) ) {
            throw new EncryptionException();
        }
    }
    //</editor-fold>
}
