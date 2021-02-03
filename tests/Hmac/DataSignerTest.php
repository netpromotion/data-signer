<?php

namespace Netpromotion\DataSigner\Test\Hmac;

use Netpromotion\DataSigner\Exception\CorruptedDataException;
use Netpromotion\DataSigner\Exception\ExpiredDataException;
use Netpromotion\DataSigner\Exception\UntrustedDataException;
use Netpromotion\DataSigner\Hmac\DataSigner;
use Netpromotion\DataSigner\Hmac\HashAlgorithm;
use Netpromotion\DataSigner\Hmac\SignedData;
use PetrKnap\Php\Enum\Exception\EnumNotFoundException;
use PHPUnit\Framework\TestCase;

class DataSignerTest extends TestCase
{
    const DATA = 'data';
    const SERIALIZED_DATA = 's:4:"data";';
    const SECRET = 'secret';
    const ALGORITHM = 'md5';
    const B64_SIGNATURE = '7TJ3nATVM5bTQ9Zg6Ie/sg==';
    const B64_SIGNATURE_EXPIRE1 = 'Tr1i3kRJwXGxGidqm7oWtg==';
    const B64_SIGNATURE_EXPIRE5 = 'O5FtDRTCx5VPs+RQB1Mbiw==';
    const NOW_TIMESTAMP = 2;

    private function getDataSigner()
    {
        $now = $this->getMockBuilder(\DateTime::class)->getMock();
        $now->method('getTimestamp')->willReturn(static::NOW_TIMESTAMP);

        /** @noinspection PhpUnhandledExceptionInspection */
        return new DataSigner(
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            static::SECRET,
            null,
            $now
        );
    }

    /**
     * @dataProvider dataGeneratesCorrectSignatures
     * @param HashAlgorithm $hashAlgorithm
     * @param int|null $expires
     * @param string $expectedSignature
     */
    public function testGeneratesCorrectSignatures(HashAlgorithm $hashAlgorithm, $expires, $expectedSignature)
    {
        $this->assertSame($expectedSignature, base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, static::SECRET, static::SERIALIZED_DATA, $expires
        )));
        $this->assertNotSame(base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, static::SECRET, static::SERIALIZED_DATA, $expires
        )), base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, 'different secret', static::SERIALIZED_DATA, $expires
        )));
    }

    public function dataGeneratesCorrectSignatures()
    {
        return [
            [HashAlgorithm::MD5(), null, '7TJ3nATVM5bTQ9Zg6Ie/sg=='],
            [HashAlgorithm::MD5(), 1, 'Tr1i3kRJwXGxGidqm7oWtg=='],
            [HashAlgorithm::SHA1(), null, 'rZhsdKv1/VVFRRLMMjXqbBMzvFY='],
            [HashAlgorithm::SHA1(), 1, 'KwaSbe2/NU83li1SqnCytfhYYuo='],
            [HashAlgorithm::SHA256(), null, 'dlDY5cb2myAVOBi7EWPr5fAnGpIgywPdX3cA8boXsos='],
            [HashAlgorithm::SHA256(), 1, 'LAiPZKAIw5gheBYGzbKATWOyFEamkAcgJeVo9Ww6YKM='],
            [HashAlgorithm::SHA384(), null, 'iKvKxN6l/tt4t5QOmN826873vyyUYNpREBBL+V/W9PObaYuIJ/gve0cM7MTfTVt8'],
            [HashAlgorithm::SHA384(), 1, 'Z2o0P06vOWNux8hf3E7A+5iqik1BrAqSyQksnP+yObe6mZg3ERbtFByzpfWxXMiK'],
            [HashAlgorithm::SHA512(), null, 'LC91vK9wCvFsvgmWXrOTjRsuz0OwEutALU+iG+PrOF+M580h5GXy4eIHAgDH+7wTStiWOXnr+PFyRmut3koShw=='],
            [HashAlgorithm::SHA512(), 1, 'lHQ6v3JJUrjTk0duQhJPDd1p3LJZiXA20x8zgPWbUGeeQCizQZOHdoQJaa6TyvkQRJ3PPxBt45QvTGnsbZB/ZQ=='],
            [HashAlgorithm::WHIRLPOOL(), null, 'CuQ0i2+3m6wwmDzp/qrRAzc+K/FjA6SLSxWaYnxwswGRwvb8OZ+NGWMQLhI8EnLtzHKBK31tC8cw2eIA/RqwEQ=='],
            [HashAlgorithm::WHIRLPOOL(), 1, 'xRpSDcEJE2+ZHpO0UFzFVaEt2XdmSFVPwfv8VCgkuEF0bDKDOHQQT/DyjJGiTM6UI0uIolj59cY3BmdfUORaHg=='],
        ];
    }

    /**
     * @dataProvider dataCheckSignatureWorks
     * @param string $signature
     * @param int|null $expires
     * @param bool $expected
     * @throws EnumNotFoundException
     */
    public function testCheckSignatureWorks($signature, $expires, $expected)
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->assertSame($expected, DataSigner::checkSignature(
            HashAlgorithm::getEnumByValue(static::ALGORITHM), static::SECRET, static::SERIALIZED_DATA, $expires, base64_decode($signature)
        ));
    }

    public function dataCheckSignatureWorks()
    {
        return [
            [static::B64_SIGNATURE, null, true],
            [static::B64_SIGNATURE, 1, false],
            [static::B64_SIGNATURE, 5, false],
            [static::B64_SIGNATURE_EXPIRE1, null, false],
            [static::B64_SIGNATURE_EXPIRE1, 1, true],
            [static::B64_SIGNATURE_EXPIRE1, 5, false],
            [static::B64_SIGNATURE_EXPIRE5, null, false],
            [static::B64_SIGNATURE_EXPIRE5, 1, false],
            [static::B64_SIGNATURE_EXPIRE5, 5, true],
        ];
    }

    /**
     * @dataProvider dataSignsData
     * @param mixed $data
     * @param string $expectedSignature
     * @param int|null $ttl
     * @throws EnumNotFoundException
     */
    public function testSignsData($data, $expectedSignature, $ttl)
    {
        $signedData = $this->getDataSigner()->signData($data, $ttl);

        $this->assertInstanceOf(SignedData::class, $signedData);
        $this->assertSame($data, $signedData->getData());
        $this->assertSame(HashAlgorithm::getEnumByValue(static::ALGORITHM), $signedData->getAlgorithm());
        $this->assertSame($expectedSignature, base64_encode($signedData->getSignature()));
        $this->assertSame($ttl ? static::NOW_TIMESTAMP + $ttl : null, $signedData->getExpires());
    }

    public function dataSignsData()
    {
        return [
            [null, 'IeV2LaJR49V6Gc/tEHMunA==', null],
            [null, '0SXBEtyrFpWbdKvEmRZN8g==', 1],
            [true, 'K/rkl/njSIRfpnhDc5Pihw==', null],
            [true, '5Keo9cGEPaLs501JAPsTng==', 1],
            [false, 'w65f72+kR4IrW36oHpV9GA==', null],
            [false, 'gz4PnSaFsI+dXhjqVxy1bA==', 1],
            [123, 'zBAsOYHoeRikD0k8IvnhWA==', null],
            [123, 'pVjiAOKYQdCJAHF3ccwVgg==', 1],
            [1.2, 'nOQlhHalAAc29fSk2HNpYA==', null],
            [1.2, 'sFoGsbkl9T2XtthxJ6NUMQ==', 1],
            [[1,2], 'i3xbgkKBJZCPbGvFIxO05A==', null],
            [[1,2], 'SD6cNkbGWRTWujsbGV5zQA==', 1],
            ['string', '56E6w44xFqiUmE6twu8e+A==', null],
            ['string', '6eicdOhLfsGpwFk4s/owGA==', 1],
            [new \stdClass(), 'Vr7lCYZJKRe6JM1LSFh4lQ==', null],
            [new \stdClass(), 'FuHn1USg0JbWlBAzh3jEkg==', 1],
        ];
    }

    /**
     * @dataProvider dataGetDataReturnsTrustedData
     * @param mixed $signedData
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     */
    public function testGetDataReturnsTrustedData($signedData)
    {
        $this->assertSame(static::DATA, $this->getDataSigner()->getData($signedData));
    }

    /**
     * @throws EnumNotFoundException
     */
    public function dataGetDataReturnsTrustedData()
    {
        $immortalSignedData = new SignedData(
            static::DATA,
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            base64_decode(static::B64_SIGNATURE)
        );
        $mortalSignedData = new SignedData(
            static::DATA,
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            base64_decode(static::B64_SIGNATURE_EXPIRE5),
            5
        );

        return [
            [$immortalSignedData],
            [$immortalSignedData->__toString()],
            [$mortalSignedData],
            [$mortalSignedData->__toString()],
        ];
    }

    /**
     * @dataProvider dataGetDataThrowsOnUntrustedData
     * @param mixed $signedData
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     */
    public function testGetDataThrowsOnUntrustedData($signedData)
    {
        $this->expectException(UntrustedDataException::class);

        $this->getDataSigner()->getData($signedData);
    }

    /**
     * @throws EnumNotFoundException
     */
    public function dataGetDataThrowsOnUntrustedData()
    {
        $signedData = new SignedData(
            static::DATA,
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            base64_decode('IeV2LaJR49V6Gc/tEHMunA==')
        );

        return [
            [$signedData],
            [$signedData->__toString()],
        ];
    }

    /**
     * @dataProvider dataGetDataThrowsOnUntrustedData
     * @param mixed $signedData
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     */
    public function testUntrustedDataExceptionContainsSerializedData($signedData)
    {
        try {
            $this->testGetDataThrowsOnUntrustedData($signedData);
        } catch (UntrustedDataException $exception) {
            $this->assertSame(static::SERIALIZED_DATA, $exception->getSerializedData());

            throw $exception;
        }
    }

    /**
     * @dataProvider dataGetDataThrowsOnExpiredData
     * @param mixed $signedData
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     * @throws ExpiredDataException
     */
    public function testGetDataThrowsOnExpiredData($signedData)
    {
        $this->expectException(ExpiredDataException::class);

        $this->getDataSigner()->getData($signedData);
    }

    /**
     * @throws EnumNotFoundException
     */
    public function dataGetDataThrowsOnExpiredData()
    {
        $signedData = new SignedData(
            static::DATA,
            HashAlgorithm::getEnumByValue(static::ALGORITHM),
            base64_decode(static::B64_SIGNATURE_EXPIRE1),
            1
        );

        return [
            [$signedData],
            [$signedData->__toString()],
        ];
    }

    /**
     * @dataProvider dataGetDataThrowsOnExpiredData
     * @param mixed $signedData
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     * @throws ExpiredDataException
     */
    public function testExpiredDataExceptionContainsSerializedData($signedData)
    {
        try {
            $this->testGetDataThrowsOnExpiredData($signedData);
        } catch (ExpiredDataException $exception) {
            $this->assertSame(static::SERIALIZED_DATA, $exception->getSerializedData());

            throw $exception;
        }
    }

    public function testWithDomainReturnsDifferentDataSigner()
    {
        $dataSigner = $this->getDataSigner();
        $dataSignerA = $dataSigner->withDomain('A');
        $this->assertNotSame($dataSigner, $dataSignerA);
    }

    public function testWithNowReturnsDifferentDataSigner()
    {
        $dataSigner = $this->getDataSigner();
        $dataSignerNow = $dataSigner->withNow(new \DateTime());
        $this->assertNotSame($dataSigner, $dataSignerNow);
    }

    public function testValidDataAreInvalidOnDifferentDomain()
    {
        $dataSignerA = $this->getDataSigner()->withDomain('A');
        $dataSignerB = $this->getDataSigner()->withDomain('B');

        $signedDataA = $dataSignerA->signData(static::DATA);

        $this->expectException(UntrustedDataException::class);

        $dataSignerB->getData($signedDataA);
    }
}
