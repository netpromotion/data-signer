<?php

namespace Netpromotion\DataSigner\Exception;

class UntrustedDataException extends DataSignerException
{
    /**
     * @var mixed
     */
    private $data;

    /**
     * @param mixed $data
     * @param string $message
     * @param int $code
     * @param null $previous
     */
    public function __construct($data, $previous = null)
    {
        parent::__construct('', 0, $previous);

        $this->data = $data;
    }

    /**
     * @return mixed
     */
    public function getData()
    {
        return $this->data;
    }
}
