<?php
namespace TurboLabIt\Encryptor\tests;

use PHPUnit\Framework\TestCase;
use TurboLabIt\Encryptor\Encryptor;
use TurboLabIt\Encryptor\EncryptionException;


/**
 * Tests for Encryptor::getSuperSecureKey($filePath, $fileName) — the auto-provisioned key file
 * ($filePath/encryptor/$fileName.key): CSPRNG-generated, chmod 0600, idempotent.
 *
 * Each test uses a throw-away sandbox dir as $filePath, so the real project is never touched and
 * the location never depends on the CWD.
 */
class SuperSecureKeyTest extends TestCase
{
    private string $sandbox;


    protected function setUp() : void
    {
        $this->sandbox = sys_get_temp_dir() . '/enc-key-' . bin2hex(random_bytes(6));
        mkdir($this->sandbox, 0700, true);
    }


    protected function tearDown() : void
    {
        $this->rrmdir($this->sandbox);
    }


    public function testGeneratesFileWhenMissing() : void
    {
        $path = $this->sandbox . '/encryptor/app.key';
        $this->assertFileDoesNotExist($path);

        $key = Encryptor::getSuperSecureKey($this->sandbox, 'app');

        $this->assertFileExists($path);
        $this->assertNotSame('', $key);
    }


    public function testKeyIs256BitHex() : void
    {
        $key = Encryptor::getSuperSecureKey($this->sandbox, 'app');

        $this->assertSame(64, strlen($key));            // 32 bytes => 64 hex chars
        $this->assertTrue(ctype_xdigit($key), 'key must be hex');
    }


    public function testFilePermissionsAre0600() : void
    {
        // skip on filesystems that don't honour chmod (e.g. some container overlay mounts)
        $probe = $this->sandbox . '/probe';
        touch($probe);
        chmod($probe, 0600);
        clearstatcache();
        if( (fileperms($probe) & 0777) !== 0600 ) {
            $this->markTestSkipped('filesystem does not honour chmod');
        }

        Encryptor::getSuperSecureKey($this->sandbox, 'app');
        clearstatcache();

        $this->assertSame(0600, fileperms($this->sandbox . '/encryptor/app.key') & 0777);
    }


    public function testAppendsDotKeyExtension() : void
    {
        Encryptor::getSuperSecureKey($this->sandbox, 'custom-name');

        // full path is $filePath/encryptor/$fileName.key
        $this->assertFileExists($this->sandbox . '/encryptor/custom-name.key');
        $this->assertFileDoesNotExist($this->sandbox . '/encryptor/custom-name');
    }


    public function testTrailingSlashInFilePathIsHandled() : void
    {
        $a = Encryptor::getSuperSecureKey($this->sandbox . '/', 'app');
        $b = Encryptor::getSuperSecureKey($this->sandbox,       'app');

        $this->assertSame($a, $b); // same file, no double slash
    }


    public function testReturnsSameKeyOnSubsequentCalls() : void
    {
        $first  = Encryptor::getSuperSecureKey($this->sandbox, 'app');
        $second = Encryptor::getSuperSecureKey($this->sandbox, 'app');

        $this->assertSame($first, $second);
    }


    public function testDifferentNamesYieldDifferentKeys() : void
    {
        $this->assertNotSame(
            Encryptor::getSuperSecureKey($this->sandbox, 'one'),
            Encryptor::getSuperSecureKey($this->sandbox, 'two')
        );
    }


    public function testGeneratedKeyIsUsableForEncryption() : void
    {
        $e    = new Encryptor( Encryptor::getSuperSecureKey($this->sandbox, 'app') );
        $data = ['id' => 7, 'role' => 'user'];

        $this->assertSame($data, $e->decrypt($e->encrypt($data)));
    }


    public function testThrowsWhenDirectoryCannotBeCreated() : void
    {
        // make '<sandbox>/encryptor' a FILE so the directory can't be created
        file_put_contents($this->sandbox . '/encryptor', 'blocker');

        $this->expectException(EncryptionException::class);
        Encryptor::getSuperSecureKey($this->sandbox, 'app');
    }


    private function rrmdir(string $dir) : void
    {
        if( !is_dir($dir) ) {
            return;
        }

        foreach( scandir($dir) as $item ) {
            if( $item === '.' || $item === '..' ) {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->rrmdir($path) : unlink($path);
        }

        rmdir($dir);
    }
}
