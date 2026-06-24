<?php
namespace TurboLabIt\Encryptor\tests;

use PHPUnit\Framework\TestCase;
use TurboLabIt\Encryptor\Encryptor;
use TurboLabIt\Encryptor\EncryptionException;


/**
 * CURRENT (v2) format: authenticated encryption (libsodium secretbox, XSalsa20-Poly1305).
 *
 * Besides round-trips, this covers the adversarial / forging scenarios described in the security
 * review: tampering (CBC-malleability style), truncation, wrong-key, the downgrade-to-legacy attack,
 * and unserialize object-injection.
 */
class EncryptorV2Test extends TestCase
{
    const SECRET = 'a-test-secret-key-1234567890';


    private function getInstance() : Encryptor
    {
        return new Encryptor(static::SECRET);
    }


    /** Build a legacy (unauthenticated AES-256-CBC) ciphertext — what a downgrade attacker submits. */
    private function makeLegacyCiphertext(mixed $data, string $secret = self::SECRET) : string
    {
        $key  = openssl_digest($secret, 'sha512', true);
        $iv   = random_bytes(openssl_cipher_iv_length('AES256'));
        $txt  = is_array($data) || is_object($data) ? serialize($data) : (string)$data;
        $blob = $iv . openssl_encrypt($txt, 'AES256', $key, OPENSSL_RAW_DATA, $iv);

        return str_ireplace(['/', '\\'], ['__ssym1__', '__ssym2__'], base64_encode($blob));
    }


    /** Flip one byte of a v2 ciphertext's raw payload, keeping the v2 framing otherwise valid. */
    private function flipByte(string $v2, int $bytePos) : string
    {
        $tag  = Encryptor::VERSION_TAG;
        $body = substr($v2, 0, -strlen($tag));
        $raw  = base64_decode(str_replace(['__ssym1__', '__ssym2__'], ['/', '\\'], $body));

        $raw[$bytePos] = $raw[$bytePos] ^ "\x01";

        $reencoded = str_ireplace(['/', '\\'], ['__ssym1__', '__ssym2__'], base64_encode($raw));
        return $reencoded . $tag;
    }


    //<editor-fold defaultstate="collapsed" desc="*** round-trip ***">
    public function testEncryptProducesV2SuffixAndIsUrlSafe() : void
    {
        $ct = $this->getInstance()->encrypt(['id' => 1]);

        $this->assertStringEndsWith(Encryptor::VERSION_TAG, $ct);
        $this->assertDoesNotMatchRegularExpression('#[/\\\\]#', $ct, 'ciphertext must be URL-safe');
    }


    public function testRoundTripArray() : void
    {
        $data = ['id' => 2, 'session_id' => '0e2daf77183764e33170718bff65946c', 'ts' => '2026-06-25 10:00:00'];
        $e    = $this->getInstance();

        $this->assertSame($data, $e->decrypt($e->encrypt($data)));
    }


    public function testRoundTripStringWithSpecialChars() : void
    {
        $plain = 'hello èà /\\ world';
        $e     = $this->getInstance();

        $this->assertSame($plain, $e->decrypt($e->encrypt($plain), unserialize: false));
    }


    public function testNonceIsRandomised() : void
    {
        $e = $this->getInstance();
        $this->assertNotSame($e->encrypt(['id' => 1]), $e->encrypt(['id' => 1]));
    }
    //</editor-fold>


    //<editor-fold defaultstate="collapsed" desc="*** forging / adversarial ***">

    /** Bit-flip in the ciphertext body is detected (defeats CBC-style malleability). */
    public function testTamperedCiphertextIsRejected() : void
    {
        $e      = $this->getInstance();
        $ct     = $e->encrypt(['id' => 2, 'role' => 'user']);
        $forged = $this->flipByte($ct, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + 3); // inside the ciphertext

        $this->expectException(EncryptionException::class);
        $e->decrypt($forged);
    }


    /** The nonce is authenticated too, so tampering it is rejected. */
    public function testTamperedNonceIsRejected() : void
    {
        $e      = $this->getInstance();
        $ct     = $e->encrypt(['id' => 2]);
        $forged = $this->flipByte($ct, 0); // first nonce byte

        $this->expectException(EncryptionException::class);
        $e->decrypt($forged);
    }


    /** Truncated ciphertext is rejected (no partial / forged decrypt). */
    public function testTruncatedCiphertextIsRejected() : void
    {
        $e         = $this->getInstance();
        $ct        = $e->encrypt(['id' => 2]);
        $truncated = substr($ct, 0, 10) . Encryptor::VERSION_TAG;

        $this->expectException(EncryptionException::class);
        $e->decrypt($truncated);
    }


    /** A ciphertext made with another key cannot be decrypted (no cross-key forgery). */
    public function testWrongKeyCannotDecrypt() : void
    {
        $ct = $this->getInstance()->encrypt(['id' => 2]);

        $this->expectException(EncryptionException::class);
        (new Encryptor('a-completely-different-secret'))->decrypt($ct);
    }


    /**
     * Downgrade attack: an attacker submits an unauthenticated legacy ciphertext to sidestep the
     * v2 authentication. The secure default ($allowLegacy = false) must refuse it.
     */
    public function testDowngradeToLegacyIsRefusedByDefault() : void
    {
        $legacy = $this->makeLegacyCiphertext(['id' => 2, 'role' => 'admin']);

        $this->expectException(EncryptionException::class);
        $this->getInstance()->decrypt($legacy); // default strict
    }


    /**
     * Object-injection forge: a malicious serialized object smuggled in a legacy ciphertext must NOT
     * be unserialized on the secure (default) path — decrypt() refuses it before unserialize() runs,
     * so the gadget's __wakeup() never fires.
     */
    public function testObjectInjectionViaDowngradeIsBlocked() : void
    {
        ForgingGadget::$pwned = false;
        $legacy = $this->makeLegacyCiphertext(new ForgingGadget());

        try {
            $this->getInstance()->decrypt($legacy); // default strict => must refuse
            $this->fail('legacy object payload was not refused');
        } catch (EncryptionException) {
            // expected
        }

        $this->assertFalse(ForgingGadget::$pwned, 'object must never be unserialized on the secure path');
    }


    /**
     * Shows WHY the default matters: if a caller explicitly opts into legacy, the same payload IS
     * unserialized (the gadget fires) — i.e. the object-injection vector is real on the legacy path,
     * which is exactly why $allowLegacy defaults to false.
     */
    public function testObjectInjectionIsPossibleOnlyWhenLegacyExplicitlyAllowed() : void
    {
        ForgingGadget::$pwned = false;
        $legacy = $this->makeLegacyCiphertext(new ForgingGadget());

        $this->getInstance()->decrypt($legacy, allowLegacy: true); // opt-in => vulnerable

        $this->assertTrue(ForgingGadget::$pwned, 'legacy + unserialize instantiates arbitrary objects');
    }
    //</editor-fold>
}


/** Test-only "gadget": flags when it is unserialized, to detect object injection. */
class ForgingGadget
{
    public static bool $pwned = false;

    public function __wakeup() : void
    {
        self::$pwned = true;
    }
}
