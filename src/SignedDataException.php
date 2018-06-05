<?php

namespace PetrKnap\Utils\Security;

class SignedDataException extends \Exception
{
    const
        GenericException = 0,
        InvalidDataException = 1,
        UntrustedDataException = 2;
}
