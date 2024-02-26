<?php
namespace TurboLabIt\Encryptor\tests;

use PHPUnit\Framework\Attributes\Depends;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use TurboLabIt\Encryptor\Encryptor;


class BundleTest extends KernelTestCase
{
    const FAKE_APP_SECRET   = 'secret-from-symfony-env';
    const TEXT_TO_ENCODE    = 'T%is is /-\ SECRùT';


    protected function getInstance() : Encryptor
    {
        return new Encryptor(static::FAKE_APP_SECRET);
    }


    public function testCreateInstance()
    {
        $encryptor = $this->getInstance();
        $this->assertInstanceOf(Encryptor::class, $encryptor );

        return $encryptor;
    }


    public function testEncryptString()
    {
        $encryptedText = $this->getInstance()->encrypt(static::TEXT_TO_ENCODE);
        $this->assertNotEquals(static::TEXT_TO_ENCODE, $encryptedText);
        return $encryptedText;
    }


    #[Depends('testEncryptString')]
    public function testDecryptString($encryptedText)
    {
        $decryptedText = $this->getInstance()->decrypt($encryptedText, false);
        $this->assertEquals(static::TEXT_TO_ENCODE, $decryptedText);
    }


    public function testEncryptDecryptArray()
    {
        $arrData = [
            "one"   => substr(str_shuffle(MD5(microtime())), 0, 10),
            "two"   => substr(str_shuffle(MD5(microtime())), 0, 10),
            "three" => [
                "one"   => substr(str_shuffle(MD5(microtime())), 0, 10),
                "six"   => substr(str_shuffle(MD5(microtime())), 0, 10),
            ]
        ];

        $encryptedText = $this->getInstance()->encrypt($arrData);
        $this->assertNotEquals($arrData, $encryptedText);

        $decryptedText = $this->getInstance()->decrypt($encryptedText, true);
        $this->assertEquals($arrData, $decryptedText);
    }
}
