<?php

namespace Netpromotion\DataSigner\Hmac;

use Netpromotion\DataSigner\SignedDataInterface;

class SignedData implements SignedDataInterface
{
    const JSON_SERIALIZED_DATA = 0;
    const JSON_ALGORITHM = 1;
    const JSON_B64_SIGNATURE = 2;

    /**
     * @var mixed
     */
    private $data;

    /**
     * @var HashAlgorithm
     */
    private $algorithm;

    /**
     * @var mixed
     */
    private $signature;

    /**
     * @param mixed $data
     * @param HashAlgorithm $algorithm
     * @param mixed $signature
     */
    public function __construct($data, HashAlgorithm $algorithm, $signature)
    {
        $this->data = $data;
        $this->algorithm = $algorithm;
        $this->signature = $signature;
    }

    /**
     * @inheritdoc
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * @return HashAlgorithm
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * @inheritdoc
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @inheritdoc
     */
    public function jsonSerialize()
    {
        return [
            static::JSON_SERIALIZED_DATA => serialize($this->data),
            static::JSON_ALGORITHM => $this->algorithm->getValue(),
            static::JSON_B64_SIGNATURE => base64_encode($this->signature),
        ];
    }

    /**
     * @inheritdoc
     */
    public function __toString()
    {
        return json_encode($this);
    }
}
