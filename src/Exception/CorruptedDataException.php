<?php

namespace Netpromotion\DataSigner\Exception;

class CorruptedDataException extends DataSignerException
{
    public function __construct($message, \Exception $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
