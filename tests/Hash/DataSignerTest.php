<?php

namespace Netpromotion\Test\DataSigner\Hash;

use Netpromotion\DataSigner\Exception\CorruptedDataException;
use Netpromotion\DataSigner\Exception\UntrustedDataException;
use Netpromotion\DataSigner\Hash\DataSigner;
use Netpromotion\DataSigner\Hash\Algorithm;
use Netpromotion\DataSigner\Hash\SignedData;
use PetrKnap\Php\Enum\Exception\EnumNotFoundException;
use PHPUnit\Framework\TestCase;

class DataSignerTest extends TestCase
{
    const DATA = 'data';
    const SERIALIZED_DATA = 's:4:"data";';
    const SECRET = 'secret';
    const ALGORITHM = Algorithm::MD5;
    const B64_SIGNATURE = '7TJ3nATVM5bTQ9Zg6Ie/sg==';

    private function getDataSigner()
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new DataSigner(
            Algorithm::getEnumByValue(static::ALGORITHM),
            static::SECRET
        );
    }

    /**
     * @dataProvider dataGeneratesCorrectSignatures
     * @param Algorithm $hashAlgorithm
     * @param string $expectedSignature
     */
    public function testGeneratesCorrectSignatures(Algorithm $hashAlgorithm, $expectedSignature)
    {
        $this->assertSame($expectedSignature, base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, static::SECRET, self::SERIALIZED_DATA
        )));
        $this->assertNotSame(base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, static::SECRET, self::SERIALIZED_DATA
        )), base64_encode(DataSigner::generateSignature(
            $hashAlgorithm, 'different secret', self::SERIALIZED_DATA
        )));
    }

    public function dataGeneratesCorrectSignatures()
    {
        return [
            [Algorithm::MD5(), '7TJ3nATVM5bTQ9Zg6Ie/sg=='],
            [Algorithm::SHA1(), 'rZhsdKv1/VVFRRLMMjXqbBMzvFY='],
            [Algorithm::SHA256(), 'dlDY5cb2myAVOBi7EWPr5fAnGpIgywPdX3cA8boXsos='],
            [Algorithm::SHA384(), 'iKvKxN6l/tt4t5QOmN826873vyyUYNpREBBL+V/W9PObaYuIJ/gve0cM7MTfTVt8'],
            [Algorithm::SHA512(), 'LC91vK9wCvFsvgmWXrOTjRsuz0OwEutALU+iG+PrOF+M580h5GXy4eIHAgDH+7wTStiWOXnr+PFyRmut3koShw=='],
            [Algorithm::WHIRLPOOL(), 'CuQ0i2+3m6wwmDzp/qrRAzc+K/FjA6SLSxWaYnxwswGRwvb8OZ+NGWMQLhI8EnLtzHKBK31tC8cw2eIA/RqwEQ=='],
            [Algorithm::CRC32(), 'JCVcbQ=='],
        ];
    }

    /**
     * @dataProvider dataCheckSignatureWorks
     * @param string $signature
     * @param bool $expected
     * @throws EnumNotFoundException
     */
    public function testCheckSignatureWorks($signature, $expected)
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->assertSame($expected, DataSigner::checkSignature(
            Algorithm::getEnumByValue(static::ALGORITHM), static::SECRET, static::SERIALIZED_DATA, base64_decode($signature)
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

    /**
     * @dataProvider dataSignsData
     * @param mixed $data
     * @param string $expectedSignature
     * @throws EnumNotFoundException
     */
    public function testSignsData($data, $expectedSignature)
    {
        $signedData = $this->getDataSigner()->signData($data);

        $this->assertInstanceOf(SignedData::class, $signedData);
        $this->assertSame($data, $signedData->getData());
        $this->assertSame(Algorithm::getEnumByValue(static::ALGORITHM), $signedData->getAlgorithm());
        $this->assertSame($expectedSignature, base64_encode($signedData->getSignature()));
    }

    public function dataSignsData()
    {
        return [
            [null, 'IeV2LaJR49V6Gc/tEHMunA=='],
            [true, 'K/rkl/njSIRfpnhDc5Pihw=='],
            [false, 'w65f72+kR4IrW36oHpV9GA=='],
            [123, 'zBAsOYHoeRikD0k8IvnhWA=='],
            [1.2, 'nOQlhHalAAc29fSk2HNpYA=='],
            [[1,2], 'i3xbgkKBJZCPbGvFIxO05A=='],
            ['string', '56E6w44xFqiUmE6twu8e+A=='],
            [new \stdClass(), 'Vr7lCYZJKRe6JM1LSFh4lQ=='],
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
        $signedData = new SignedData(
            static::DATA,
            Algorithm::getEnumByValue(static::ALGORITHM),
            base64_decode(static::B64_SIGNATURE)
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
            Algorithm::getEnumByValue(static::ALGORITHM),
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
}
