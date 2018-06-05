<?php

namespace Netpromotion\DataSigner;

use PetrKnap\Php\Enum\ConstantsAsMembers;
use PetrKnap\Php\Enum\Enum;

/**
 * @method static HashAlgorithm CRC32
 * @method static HashAlgorithm MD5
 * @method static HashAlgorithm SHA1
 * @method static HashAlgorithm SHA256
 * @method static HashAlgorithm SHA384
 * @method static HashAlgorithm SHA512
 * @method static HashAlgorithm WHIRLPOOL
 */
class HashAlgorithm extends Enum
{
    use ConstantsAsMembers;

    const CRC32 = 'crc32';
    const MD5 = 'md5';
    const SHA1 = 'sha1';
    const SHA256 = 'sha256';
    const SHA384 = 'sha384';
    const SHA512 = 'sha512';
    const WHIRLPOOL = 'whirlpool';

    /**
     * @inheritdoc
     */
    public function __toString()
    {
        return $this->getValue();
    }
}
