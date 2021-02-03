<?php

namespace Netpromotion\DataSigner\Hmac;

use PetrKnap\Php\Enum\Enum;

/**
 * @method static HashAlgorithm MD5
 * @method static HashAlgorithm SHA1
 * @method static HashAlgorithm SHA256
 * @method static HashAlgorithm SHA384
 * @method static HashAlgorithm SHA512
 * @method static HashAlgorithm WHIRLPOOL
 */
class HashAlgorithm extends Enum
{
    /**
     * @inheritdoc
     */
    protected function members()
    {
        $members = [];
        foreach (hash_algos() as $algorithm) {
            $members[mb_strtoupper($algorithm)] = $algorithm;
        }
        return $members;
    }

    /**
     * @inheritdoc
     */
    public function __toString()
    {
        return $this->getValue();
    }
}
