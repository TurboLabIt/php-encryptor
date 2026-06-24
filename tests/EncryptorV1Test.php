<?php
namespace TurboLabIt\Encryptor\tests;

use PHPUnit\Framework\TestCase;
use TurboLabIt\Encryptor\Encryptor;
use TurboLabIt\Encryptor\EncryptionException;


/**
 * LEGACY (v1) format: unauthenticated AES-256-CBC.
 *
 * encrypt() no longer produces this format, so these tests build v1 ciphertexts with the original
 * scheme and verify that decrypt() still reads them — but ONLY when the caller opts in with
 * $allowLegacy = true, and refuses them otherwise (secure-by-default).
 */
class EncryptorV1Test extends TestCase
{
    const SECRET = 'a-test-secret-key-1234567890';


    private function getInstance() : Encryptor
    {
        return new Encryptor(static::SECRET);
    }


    /** Reproduce the original (pre-upgrade) AES-256-CBC ciphertext format (no version suffix). */
    private function makeLegacyCiphertext(mixed $data, string $secret = self::SECRET) : string
    {
        $key  = openssl_digest($secret, 'sha512', true);
        $iv   = random_bytes(openssl_cipher_iv_length('AES256'));
        $txt  = is_array($data) || is_object($data) ? serialize($data) : (string)$data;
        $blob = $iv . openssl_encrypt($txt, 'AES256', $key, OPENSSL_RAW_DATA, $iv);

        return str_ireplace(['/', '\\'], ['__ssym1__', '__ssym2__'], base64_encode($blob));
    }


    public function testLegacyStringDecryptsWhenAllowed() : void
    {
        $plain  = 'T%is is /-\\ SECRùT';
        $legacy = $this->makeLegacyCiphertext($plain);

        $this->assertSame($plain, $this->getInstance()->decrypt($legacy, unserialize: false, allowLegacy: true));
    }


    public function testLegacyArrayDecryptsWhenAllowed() : void
    {
        $data   = ['userId' => 42, 'scope' => 'newsletterUnsubscribeUrl', 'nested' => ['a' => 1]];
        $legacy = $this->makeLegacyCiphertext($data);

        $this->assertSame($data, $this->getInstance()->decrypt($legacy, allowLegacy: true));
    }


    public function testLegacyIsRefusedByDefault() : void
    {
        $legacy = $this->makeLegacyCiphertext(['userId' => 42]);

        $this->expectException(EncryptionException::class);
        $this->getInstance()->decrypt($legacy); // default $allowLegacy = false
    }


    public function testLegacyWithWrongKeyFails() : void
    {
        $legacy = $this->makeLegacyCiphertext(['userId' => 42], static::SECRET);

        // wrong key => bad padding or garbage that won't unserialize
        $this->expectException(\Exception::class);
        (new Encryptor('a-completely-different-secret'))->decrypt($legacy, allowLegacy: true);
    }


    public function testLegacyTooShortInputThrows() : void
    {
        // non-v2 string that base64-decodes to fewer bytes than the IV length
        $tooShort = str_ireplace(['/', '\\'], ['__ssym1__', '__ssym2__'], base64_encode('short'));

        $this->expectException(EncryptionException::class);
        $this->getInstance()->decrypt($tooShort, allowLegacy: true);
    }


    public function testEmptyInputReturnsEmpty() : void
    {
        $this->assertSame('', $this->getInstance()->decrypt('', allowLegacy: true));
    }
}
