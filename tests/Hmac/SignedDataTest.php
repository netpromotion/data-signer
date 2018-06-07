<?php

namespace Netpromotion\Test\DataSigner\Hmac;

use Netpromotion\DataSigner\Hmac\HashAlgorithm;
use Netpromotion\DataSigner\Hmac\SignedData;
use PHPUnit\Framework\TestCase;

class SignedDataTest extends TestCase
{
    private function getSignedDataAsObject()
    {
        return new SignedData('data', HashAlgorithm::MD5(), base64_decode('7TJ3nATVM5bTQ9Zg6Ie/sg=='));
    }

    private function getSignatureDataAsJsonString()
    {
        return "[\"s:4:\\\"data\\\";\",\"md5\",\"7TJ3nATVM5bTQ9Zg6Ie\/sg==\"]";
    }

    public function testJsonSerializationWorks()
    {
        $this->assertSame($this->getSignatureDataAsJsonString(), json_encode($this->getSignedDataAsObject()));
    }
}
