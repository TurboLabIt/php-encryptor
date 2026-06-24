<?php
namespace TurboLabIt\Encryptor\tests;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use TurboLabIt\Encryptor\Encryptor;


class BundleTest extends KernelTestCase
{
    const FAKE_APP_SECRET = 'secret-from-symfony-env';


    public function testServiceInstance() : void
    {
        $encryptor = new Encryptor(static::FAKE_APP_SECRET);
        $this->assertInstanceOf(Encryptor::class, $encryptor);
    }
}
