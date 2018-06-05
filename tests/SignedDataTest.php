<?php

namespace Netpromotion\Test\DataSigner;

use Netpromotion\DataSigner\HashAlgorithm;
use Netpromotion\DataSigner\SignedData;
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

    private function getSignedDataAsString()
    {
        return "C:34:\"Netpromotion\DataSigner\SignedData\":51:{[\"s:4:\\\"data\\\";\",\"md5\",\"7TJ3nATVM5bTQ9Zg6Ie\/sg==\"]}";
    }

    public function testSerializationWorks()
    {
        $this->assertSame($this->getSignedDataAsString(), serialize($this->getSignedDataAsObject()));
    }

    public function testDeserializationWorks()
    {
        $this->assertEquals($this->getSignedDataAsObject(), unserialize($this->getSignedDataAsString()));
    }

    public function testJsonSerializationWorks()
    {
        $this->assertSame($this->getSignatureDataAsJsonString(), json_encode($this->getSignedDataAsObject()));
    }
}
