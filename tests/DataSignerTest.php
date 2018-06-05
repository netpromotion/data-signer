<?php

namespace Netpromotion\Test\DataSigner;

use Netpromotion\DataSigner\DataSigner;
use Netpromotion\DataSigner\Exception\UntrustedDataException;
use Netpromotion\DataSigner\HashAlgorithm;
use Netpromotion\DataSigner\SignedData;

class DataSignerTest extends \PHPUnit_Framework_TestCase
{
    const DATA = 'data';
    const SECRET = 'secret';
    const ALGORITHM = HashAlgorithm::MD5;
    const B64_SIGNATURE = '7TJ3nATVM5bTQ9Zg6Ie/sg==';

    private function getDataSigner()
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new DataSigner(
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            static::SECRET
        );
    }

    /**
     * @dataProvider dataGeneratesCorrectSignatures
     * @param HashAlgorithm $hashAlgorithm
     * @param mixed $data
     * @param string $expectedSignature
     */
    public function testGeneratesCorrectSignatures(HashAlgorithm $hashAlgorithm, $data, $expectedSignature)
    {
        $this->assertSame($expectedSignature, base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, static::SECRET, $data
        )));
        $this->assertNotSame(base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, static::SECRET, $data
        )), base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, 'different secret', $data
        )));
    }

    public function dataGeneratesCorrectSignatures()
    {
        /** @noinspection PhpUndefinedMethodInspection */
        return [
            // Different data
            [HashAlgorithm::MD5(), null, 'IeV2LaJR49V6Gc/tEHMunA=='],
            [HashAlgorithm::MD5(), true, 'K/rkl/njSIRfpnhDc5Pihw=='],
            [HashAlgorithm::MD5(), false, 'w65f72+kR4IrW36oHpV9GA=='],
            [HashAlgorithm::MD5(), 123, 'zBAsOYHoeRikD0k8IvnhWA=='],
            [HashAlgorithm::MD5(), 1.2, 'nOQlhHalAAc29fSk2HNpYA=='],
            [HashAlgorithm::MD5(), [1,2], 'i3xbgkKBJZCPbGvFIxO05A=='],
            [HashAlgorithm::MD5(), 'string', '56E6w44xFqiUmE6twu8e+A=='],
            [HashAlgorithm::MD5(), new \stdClass(), 'Vr7lCYZJKRe6JM1LSFh4lQ=='],
            // Different algorithms
            [HashAlgorithm::SHA1(), '', 'XD+VGNBrMTz7RibfIAn+icyVDr0='],
            [HashAlgorithm::SHA256(), '', '79nnfiu+oOz5L8vBntu+QtxEU4hk4HFaQiWuKaGkidM='],
            [HashAlgorithm::SHA384(), '', 's8sfF9TUaNxe5aFRc3y8c3SfwlKCCClAyE+G3hBetcHXnh4lVESdq/L0JKmpyYGt'],
            [HashAlgorithm::SHA512(), '', 'Y4K9erMW62MV36W5RhFD7iIJn2V+rAthjNnqiGz+XVx8M+5qBAHNNYt73hGWtGnDym8aRjSgbSiRlC1FwbyKsg=='],
            [HashAlgorithm::WHIRLPOOL(), '', 'rdOL3cqJpYYbkKK3FZhlIGdL2v3NgQJXly4Sj9C33RBam4DX6yMvqGQFYP0A15FlcxGch/00wk0d7CltYQUn9g=='],
            [HashAlgorithm::CRC32(), '', 'U3iGng=='],
        ];
    }

    /**
     * @dataProvider dataCheckSignatureWorks
     * @param string $signature
     * @param bool $expected
     */
    public function testCheckSignatureWorks($signature, $expected)
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->assertSame($expected, DataSigner::checkSignature(
            HashAlgorithm::getEnumByValue(static::ALGORITHM), static::SECRET, static::DATA, base64_decode($signature)
        ));
    }

    public function dataCheckSignatureWorks()
    {
        return [
            [static::B64_SIGNATURE, true],
            ['IeV2LaJR49V6Gc/tEHMunA==', false],
            ['nOQlhHalAAc29fSk2HNpYA==', false],
        ];
    }

    public function testSignsData()
    {
        $signedData = $this->getDataSigner()->signData(static::DATA);

        $this->assertInstanceOf(SignedData::class, $signedData);
        $this->assertSame(static::DATA, $signedData->getData());
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->assertSame(HashAlgorithm::getEnumByValue(static::ALGORITHM), $signedData->getAlgorithm());
        $this->assertSame(static::B64_SIGNATURE, base64_encode($signedData->getSignature()));
    }

    public function testGetDataReturnsTrustedData()
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->assertSame(static::DATA, $this->getDataSigner()->getData(new SignedData(
            static::DATA,
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            base64_decode(static::B64_SIGNATURE)
        )));
    }

    public function testGetDataThrowsOnUntrustedData()
    {
        $this->expectException(UntrustedDataException::class);

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->getDataSigner()->getData(new SignedData(
            static::DATA,
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            base64_decode('IeV2LaJR49V6Gc/tEHMunA==')
        ));
    }

    public function testUntrustedDataExceptionContainsData()
    {
        try {
            $this->testGetDataThrowsOnUntrustedData();
        } catch (UntrustedDataException $exception) {
            $this->assertSame(static::DATA, $exception->getData());

            /** @noinspection PhpUnhandledExceptionInspection */
            throw $exception;
        }
    }
}
