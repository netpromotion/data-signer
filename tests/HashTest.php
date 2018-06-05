<?php

namespace Netpromotion\DataSigner\Test;

use Netpromotion\DataSigner\Hash;
use PHPUnit\Framework\TestCase;

class HashTest extends TestCase
{
    private function hash_test($fn, $data, $length)
    {
        foreach ($data as $value => $expectation) {
            $hash = $fn($value);

            $this->assertEquals($length, strlen($hash));

            $this->assertEquals($expectation, $hash);
        }
    }

    public function testBase64Sha512Works()
    {
        $this->hash_test(
            function ($a) {
                return Hash::B64SHA512($a);
            },
            array(
                "" => "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg",
                "B64SHA512" => "4gN1ufF6zsj1fZkkvXGQ3l9csdUacfrDM0DayNzXER1ftko/QYykMae1k2UM/kPKonPKRmiUP5ONY8LX26aONA"
            ),
            Hash::B64SHA512length
        );
    }

    public function testBase64Sha384Works()
    {
        $this->hash_test(
            function ($a) {
                return Hash::B64SHA384($a);
            },
            array(
                "" => "OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb",
                "B64SHA384" => "rra1t/gN0nXnQ3r7wbn5brsoEXbbCXALrkiXHgW7wQK7nhoZqUMeBn4/j2WWOhRo"
            ),
            Hash::B64SHA384length
        );
    }

    public function testBase64Sha256Works()
    {
        $this->hash_test(
            function ($a) {
                return Hash::B64SHA256($a);
            },
            array(
                "" => "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
                "B64SHA256" => "SzeITr6pPnbhGbXXp145Ih5IIURlteDlxvPFVdhCYlQ"
            ),
            Hash::B64SHA256length
        );
    }

    public function testBase64Sha1Works()
    {
        $this->hash_test(
            function ($a) {
                return Hash::B64SHA1($a);
            },
            array(
                "" => "2jmj7l5rSw0yVb/vlWAYkK/YBwk",
                "B64SHA1" => "N1GpCoLnYk3sBJ+8mVfVLyCK2Ps"
            ),
            Hash::B64SHA1length
        );
    }

    public function testBase64Md5Works()
    {
        $this->hash_test(
            function ($a) {
                return Hash::B64MD5($a);
            },
            array(
                "" => "1B2M2Y8AsgTpgAmY7PhCfg",
                "B64MD5" => "i2OtmWyPZI88FRf6kQxLdw"
            ),
            Hash::B64MD5length
        );
    }

    public function testRandomByteGeneratorWorks()
    {
        for ($i = 0; $i < 10; $i++) {
            $first = Hash::RandomBytes($i + 1);
            $second = Hash::RandomBytes($i + 1);

            $this->assertTrue($first !== $second);

            $this->assertEquals(($i + 1) * 2, strlen($first));
            $this->assertEquals(($i + 1) * 2, strlen($second));
        }
    }


    public function testBase64ToUrlAndUrlToBase64ConvertersWork()
    {
        $s1 = "This+isn/t+valid+B64==";
        $s2 = Hash::B642URL($s1);
        $s3 = Hash::URL2B64($s2);

        $this->assertEquals($s1, $s3);
        $this->assertFalse(strpos($s2, "+"));
        $this->assertFalse(strpos($s2, "/"));
        $this->assertFalse(strpos($s2, "="));
    }
}
