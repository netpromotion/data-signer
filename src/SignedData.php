<?php

namespace Netpromotion\DataSigner;

use Netpromotion\DataSigner\Exception\CorruptedDataException;
use PetrKnap\Php\Enum\Exception\EnumNotFoundException;

class SignedData implements \JsonSerializable, \Serializable
{
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
     * @return mixed
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
     * @return mixed
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
    public function serialize()
    {
        return json_encode($this);
    }

    /**
     * @inheritdoc
     * @throws CorruptedDataException
     */
    public function unserialize($serialized)
    {
        $data = json_decode($serialized, true);

        try {
            $this->data = unserialize($data[0]);
            $this->algorithm = HashAlgorithm::getEnumByValue($data[1]);
            $this->signature = base64_decode($data[2]);

            if (false === $this->signature) {
                throw new CorruptedDataException(sprintf('Wrong signature: "%s"', $data[2]));
            }
        } catch (EnumNotFoundException $exception) {
            throw new CorruptedDataException('Unknown hash algorithm', $exception);
        }
    }

    /**
     * @inheritdoc
     */
    public function __toString()
    {
        return $this->serialize();
    }
}
