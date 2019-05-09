<?php

namespace Netpromotion\DataSigner;

interface SignedDataInterface extends \JsonSerializable
{
    /**
     * @return mixed
     */
    public function getData();

    /**
     * @return mixed
     */
    public function getSignature();

    /**
     * @return null|int
     */
    public function getExpires();
}
