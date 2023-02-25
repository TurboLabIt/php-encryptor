# php-encryptor
The easiest tool to encrypt/decrypt strings and arrays in PHP


## 📦 1. Install it with composer

````bash
composer config repositories.turbolabit/php-encryptor git https://github.com/TurboLabIt/php-encryptor.git
composer require turbolabit/php-encryptor:dev-main

````

## 🔁 2. Symfony usage

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
````

See: [Usage](https://github.com/TurboLabIt/php-encryptor/blob/main/tests/EncryptorTest.php)


## 3. ⚙️ Symfony custom configuration (optional)

````yaml
# config/services.yaml
TurboLabIt\Encryptor\Encryptor:
  arguments:
    $secretKey: '%env(APP_SECRET)%'

````

See: [services.yaml](https://github.com/TurboLabIt/php-encryptor/blob/main/src/Resources/config/services.yaml)


## 🧪 Test it

````bash
git clone git@github.com:TurboLabIt/php-encryptor.git
cd php-encryptor
clear && bash script/test_runner.sh

````
