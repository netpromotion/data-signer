<?php

namespace Netpromotion\DataSigner;

use Netpromotion\DataSigner\Exception\CorruptedDataException;
use Netpromotion\DataSigner\Exception\ExpiredDataException;
use Netpromotion\DataSigner\Exception\UntrustedDataException;

interface DataSignerInterface
{
    /**
     * @param string|null $name
     * @return DataSignerInterface
     */
    public function withDomain($name);

    /**
     * @param mixed $data
     * @param int|null $timeToLive seconds
     * @return SignedDataInterface
     */
    public function signData($data, $timeToLive = null);

    /**
     * @param SignedDataInterface|string $dataOrDataAsString
     * @return mixed
     * @throws CorruptedDataException
     * @throws UntrustedDataException
     * @throws ExpiredDataException
     */
    public function getData($dataOrDataAsString);
}
