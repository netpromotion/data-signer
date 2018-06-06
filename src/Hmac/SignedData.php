<?php

namespace Netpromotion\DataSigner\Hmac;

use Netpromotion\DataSigner\SignedDataInterface;

class SignedData implements SignedDataInterface
{
    const JSON_SERIALIZED_DATA = 0;
    const JSON_ALGORITHM = 1;
    const JSON_B64_SIGNATURE = 2;
    const JSON_EXPIRE = 3;

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
     * @var int|null
     */
    private $expire;

    /**
     * @param mixed $data
     * @param HashAlgorithm $algorithm
     * @param mixed $signature
     * @param int|null $expire
     */
    public function __construct($data, HashAlgorithm $algorithm, $signature, $expire = null)
    {
        $this->data = $data;
        $this->algorithm = $algorithm;
        $this->signature = $signature;
        $this->expire = $expire;
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
    public function getExpire()
    {
        return $this->expire;
    }

    /**
     * @inheritdoc
     */
    public function jsonSerialize()
    {
        $data = [
            static::JSON_SERIALIZED_DATA => serialize($this->data),
            static::JSON_ALGORITHM => $this->algorithm->getValue(),
            static::JSON_B64_SIGNATURE => base64_encode($this->signature)
        ];

        if (null !== $this->expire) {
            $data[static::JSON_EXPIRE] = $this->expire;
        }

        return $data;
    }

    /**
     * @inheritdoc
     */
    public function __toString()
    {
        return json_encode($this);
    }
}
