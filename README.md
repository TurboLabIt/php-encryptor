# php-encryptor
A single, zero-config service with encrypt() and decrypt() methods to safely share or expose confidential data


## 📦 1. Install it with composer

````bash
symfony composer require turbolabit/php-encryptor:dev-main

````

## 🔁 2. Symfony usage

````php
<?php
use TurboLabIt\Encryptor\Encryptor;


class Property
{
    protected string $bookingToken = '12345678';
    
    public function __construct(protected Encryptor $encryptor)
    {}
    
    
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

See: [Usage](https://github.com/TurboLabIt/php-encryptor/blob/main/tests/BundleTest.php)


## 3. ⚙️ Symfony custom configuration (optional)

````yaml
# config/services.yaml
TurboLabIt\Encryptor\Encryptor:
  arguments:
    $secretKey: '%env(APP_SECRET)%'

````

See: [services.yaml](https://github.com/TurboLabIt/php-encryptor/blob/main/config/services.yaml)


## 🧪 Test it

````bash
git clone git@github.com:TurboLabIt/php-encryptor.git
cd php-encryptor
bash script/symfony-bundle-tester.sh

````
