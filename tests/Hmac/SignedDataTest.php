<?php

namespace Netpromotion\Test\DataSigner\Hmac;

use Netpromotion\DataSigner\Hmac\HashAlgorithm;
use Netpromotion\DataSigner\Hmac\SignedData;
use PHPUnit\Framework\TestCase;

class SignedDataTest extends TestCase
{
    private function getImmortalSignedDataAsObject()
    {
        return new SignedData('data', HashAlgorithm::MD5(), base64_decode('7TJ3nATVM5bTQ9Zg6Ie/sg=='));
    }

    private function getImmortalSignatureDataAsJsonString()
    {
        return "[\"s:4:\\\"data\\\";\",\"md5\",\"7TJ3nATVM5bTQ9Zg6Ie\/sg==\"]";
    }

    private function getMortalSignedDataAsObject()
    {
        return new SignedData('data', HashAlgorithm::MD5(), base64_decode('7TJ3nATVM5bTQ9Zg6Ie/sg=='), 123);
    }

    private function getMortalSignatureDataAsJsonString()
    {
        return "[\"s:4:\\\"data\\\";\",\"md5\",\"7TJ3nATVM5bTQ9Zg6Ie\/sg==\",123]";
    }

    public function testJsonSerializationWorks()
    {
        $this->assertSame($this->getImmortalSignatureDataAsJsonString(), json_encode($this->getImmortalSignedDataAsObject()));
        $this->assertSame($this->getMortalSignatureDataAsJsonString(), json_encode($this->getMortalSignedDataAsObject()));
    }
}
