<?php

namespace Netpromotion\DataSigner;

use Netpromotion\DataSigner\Exception\CorruptedDataException;
use Netpromotion\DataSigner\Exception\UntrustedDataException;
use PetrKnap\Php\Enum\Exception\EnumNotFoundException;

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
     * @param mixed $serializedData
     * @return mixed
     */
    public static function generateSignature(HashAlgorithm $hashAlgorithm, $secret, $serializedData)
    {
        return hash_hmac($hashAlgorithm, $serializedData, $secret, true);
    }

    /**
     * @internal public for test purpose only
     * @param HashAlgorithm $hashAlgorithm
     * @param string $secret
     * @param mixed $serializedData
     * @param mixed $signature
     * @return bool
     */
    public static function checkSignature(HashAlgorithm $hashAlgorithm, $secret, $serializedData, $signature)
    {
        return static::generateSignature($hashAlgorithm, $secret, $serializedData) === $signature;
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
            serialize($data)
        ));
    }

    /**
     * @param SignedData|string $signedDataAsString
     * @return mixed
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     */
    public function getData($signedDataOrSignedDataAsString)
    {
        if ($signedDataOrSignedDataAsString instanceof SignedData) {
            $signedDataAsString = $signedDataOrSignedDataAsString->__toString();
        } else {
            $signedDataAsString = $signedDataOrSignedDataAsString;
        }

        $decoded = json_decode($signedDataAsString, true, 2);

        if (null === $decoded) {
            throw new CorruptedDataException('json_decode failed', new \Exception(
                json_last_error_msg(),
                json_last_error()
            ));
        }

        $signature = base64_decode(array_pop($decoded));
        try {
            $hashAlgorithm = HashAlgorithm::getEnumByValue(array_pop($decoded));
        } catch (EnumNotFoundException $exception) {
            throw new CorruptedDataException('Unknown HashAlgorithm', $exception);
        }
        $serializedData = array_pop($decoded);

        if (!static::checkSignature($hashAlgorithm, $this->secret, $serializedData, $signature)) {
            throw new UntrustedDataException($serializedData);
        }

        return unserialize($serializedData);
    }
}
