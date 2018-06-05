<?php

namespace Netpromotion\DataSigner;

use Netpromotion\DataSigner\Exception\CorruptedDataException;
use Netpromotion\DataSigner\Exception\UntrustedDataException;

interface DataSignerInterface
{
    /**
     * @param mixed $data
     * @return SignedDataInterface
     */
    public function signData($data);

    /**
     * @param SignedDataInterface|string $dataOrDataAsString
     * @return mixed
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     */
    public function getData($dataOrDataAsString);
}
