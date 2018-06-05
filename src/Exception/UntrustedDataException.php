<?php

namespace Netpromotion\DataSigner\Exception;

class UntrustedDataException extends DataSignerException
{
    /**
     * @var string
     */
    private $serializedData;

    /**
     * @param string $serializedData
     * @param null $previous
     */
    public function __construct($serializedData, $previous = null)
    {
        parent::__construct('', 0, $previous);

        $this->serializedData = $serializedData;
    }

    /**
     * @return string
     */
    public function getSerializedData()
    {
        return $this->serializedData;
    }
}
