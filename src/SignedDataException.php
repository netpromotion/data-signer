<?php

namespace Netpromotion\DataSigner;

class SignedDataException extends \Exception
{
    const
        GenericException = 0,
        InvalidDataException = 1,
        UntrustedDataException = 2;
}
