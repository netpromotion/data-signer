<?php

namespace Netpromotion\DataSigner\Hash;

use Netpromotion\DataSigner\SignedDataInterface;

class SignedData implements SignedDataInterface
{
    /**
     * @var mixed
     */
    private $data;

    /**
     * @var Algorithm
     */
    private $algorithm;

    /**
     * @var mixed
     */
    private $signature;

    /**
     * @param mixed $data
     * @param Algorithm $algorithm
     * @param mixed $signature
     */
    public function __construct($data, Algorithm $algorithm, $signature)
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
     * @return Algorithm
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
            serialize($this->data),
            $this->algorithm->getValue(),
            base64_encode($this->signature),
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
