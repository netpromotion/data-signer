<?php

namespace Netpromotion\DataSigner\Hash;

use PetrKnap\Php\Enum\ConstantsAsMembers;
use PetrKnap\Php\Enum\Enum;

/**
 * @method static Algorithm CRC32
 * @method static Algorithm MD5
 * @method static Algorithm SHA1
 * @method static Algorithm SHA256
 * @method static Algorithm SHA384
 * @method static Algorithm SHA512
 * @method static Algorithm WHIRLPOOL
 */
class Algorithm extends Enum
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
