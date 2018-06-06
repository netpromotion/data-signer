<?php

namespace Netpromotion\DataSigner\Hash;

use Netpromotion\DataSigner\DataSignerInterface;
use Netpromotion\DataSigner\Exception\CorruptedDataException;
use Netpromotion\DataSigner\Exception\UntrustedDataException;
use Netpromotion\DataSigner\SignedDataInterface;
use Nunzion\Expect;
use PetrKnap\Php\Enum\Exception\EnumNotFoundException;

class DataSigner implements DataSignerInterface
{
    /**
     * @var Algorithm
     */
    private $hashAlgorithm;

    /**
     * @var string
     */
    private $secret;

    /**
     * @param Algorithm $hashAlgorithm
     * @param string $secret
     */
    public function __construct(Algorithm $hashAlgorithm, $secret)
    {
        Expect::that($secret)->isString()->isNotEmpty();

        $this->hashAlgorithm = $hashAlgorithm;
        $this->secret = $secret;
    }

    /**
     * @internal public for test purpose only
     * @param Algorithm $hashAlgorithm
     * @param string $secret
     * @param string $serializedData
     * @return mixed
     */
    public static function generateSignature(Algorithm $hashAlgorithm, $secret, $serializedData)
    {
        Expect::that($secret)->isString()->isNotEmpty();
        Expect::that($serializedData)->isString()->isNotEmpty();

        return hash_hmac($hashAlgorithm, $serializedData, $secret, true);
    }

    /**
     * @internal public for test purpose only
     * @param Algorithm $hashAlgorithm
     * @param string $secret
     * @param string $serializedData
     * @param mixed $signature
     * @return bool
     */
    public static function checkSignature(Algorithm $hashAlgorithm, $secret, $serializedData, $signature)
    {
        Expect::that($signature)->isNotNull();

        return static::generateSignature($hashAlgorithm, $secret, $serializedData) === $signature;
    }

    /**
     * @inheritdoc
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
     * @inheritdoc
     */
    public function getData($dataOrDataAsString)
    {
        if ($dataOrDataAsString instanceof SignedDataInterface) {
            Expect::that($dataOrDataAsString)->isInstanceOf(SignedData::class);
            $signedDataAsString = json_encode($dataOrDataAsString);
        } else {
            Expect::that($dataOrDataAsString)->isString()->isNotEmpty();
            $signedDataAsString = $dataOrDataAsString;
        }

        $decoded = json_decode($signedDataAsString, true, 2);

        if (null === $decoded) {
            throw new CorruptedDataException('json_decode failed', new \Exception(
                json_last_error_msg(),
                json_last_error()
            ));
        }

        $serializedData = $decoded[SignedData::JSON_SERIALIZED_DATA];
        try {
            $hashAlgorithm = Algorithm::getEnumByValue($decoded[SignedData::JSON_ALGORITHM]);
        } catch (EnumNotFoundException $exception) {
            throw new CorruptedDataException('Unknown HashAlgorithm', $exception);
        }
        $signature = base64_decode($decoded[SignedData::JSON_B64_SIGNATURE]);

        if (!static::checkSignature($hashAlgorithm, $this->secret, $serializedData, $signature)) {
            throw new UntrustedDataException($serializedData);
        }

        return unserialize($serializedData);
    }
}
