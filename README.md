# php-encryptor
The easiest tool to encrypt/decrypt strings and arrays in PHP

## 📦 Install it with composer

````bash
composer config repositories.TurboLabIt/php-encryptor git https://github.com/TurboLabIt/php-encryptor.git
composer require turbolabit/php-encryptor:dev-main

````

## 🔁 Symfony usage

````yaml
# config/services.yaml
TurboLabIt\Encryptor\Encryptor:
  arguments:
    $secretKey: '%env(APP_SECRET)%'
````

````php
<?php
use TurboLabIt\Encryptor\Encryptor;

class Property
{
    protected Encryptor $encryptor;
    protected string $bookingToken = '12345678';
    
    public function __construct(Encryptor $encryptor)
    {
        $this->encryptor = $encryptor;
    }
    
    
    public function getBookingData() : string
    {
        $arrData = [
            "name"          => 'aabbcc',
            "bookingToken"  => $this->bookingToken;
        ]    

        return $this->encryptor->encrypt($arrData);
    }
    
    
    public function decodeBookingData(string $text) : array
    {
        return $this->encryptor->decrypt($text);
    }
}
```

See: [Usage](https://github.com/TurboLabIt/php-encryptor/blob/main/tests/EncryptorTest.php)
