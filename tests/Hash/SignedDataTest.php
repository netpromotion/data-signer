<?php

namespace Netpromotion\Test\DataSigner\Hash;

use Netpromotion\DataSigner\Hash\Algorithm;
use Netpromotion\DataSigner\Hash\SignedData;
use PHPUnit\Framework\TestCase;

class SignedDataTest extends TestCase
{
    private function getSignedDataAsObject()
    {
        return new SignedData('data', Algorithm::MD5(), base64_decode('7TJ3nATVM5bTQ9Zg6Ie/sg=='));
    }

    private function getSignatureDataAsJsonString()
    {
        return "{\"d\":\"s:4:\\\"data\\\";\",\"a\":\"md5\",\"s\":\"7TJ3nATVM5bTQ9Zg6Ie\/sg==\"}";
    }

    public function testJsonSerializationWorks()
    {
        $this->assertSame($this->getSignatureDataAsJsonString(), json_encode($this->getSignedDataAsObject()));
    }
}
