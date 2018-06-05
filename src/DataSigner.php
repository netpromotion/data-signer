<?php

namespace Netpromotion\DataSigner;

use Netpromotion\DataSigner\Exception\UntrustedDataException;

class DataSigner
{
    /**
     * @var HashAlgorithm
     */
    private $hashAlgorithm;

    /**
     * @var string
     */
    private $secret;

    /**
     * @param HashAlgorithm $hashAlgorithm
     * @param string $secret
     */
    public function __construct(HashAlgorithm $hashAlgorithm, $secret)
    {
        $this->hashAlgorithm = $hashAlgorithm;
        $this->secret = $secret;
    }

    /**
     * @internal public for test purpose only
     * @param HashAlgorithm $hashAlgorithm
     * @param string $secret
     * @param mixed $data
     * @return mixed
     */
    public static function generateSignature(HashAlgorithm $hashAlgorithm, $secret, $data)
    {
        return hash_hmac($hashAlgorithm, serialize($data), $secret, true);
    }

    /**
     * @internal public for test purpose only
     * @param HashAlgorithm $hashAlgorithm
     * @param string $secret
     * @param mixed $data
     * @param mixed $signature
     * @return bool
     */
    public static function checkSignature(HashAlgorithm $hashAlgorithm, $secret, $data, $signature)
    {
        return static::generateSignature($hashAlgorithm, $secret, $data) === $signature;
    }

    /**
     * @param mixed $data
     * @return SignedData
     */
    public function signData($data)
    {
        return new SignedData($data, $this->hashAlgorithm, static::generateSignature(
            $this->hashAlgorithm,
            $this->secret,
            $data
        ));
    }

    /**
     * @param SignedData $signedData
     * @return mixed
     * @throws UntrustedDataException
     */
    public function getData(SignedData $signedData)
    {
        $data = $signedData->getData();
        if (!static::checkSignature($signedData->getAlgorithm(), $this->secret, $data, $signedData->getSignature())) {
            throw new UntrustedDataException($data);
        }

        return $data;
    }
}
