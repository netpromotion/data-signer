<?php

namespace Netpromotion\DataSigner;

/**
 * Provides methods for signing data
 *
 * All internal methods are covered using getter and setter. Unsigned data set to the property `UnsignedData` and signed data set to the property `SignedData` directly.
 *
 * To determine the credibility of the data, check the property `IsTrusted`.
 *
 * @property mixed UnsignedData Unsigned data
 * @property bool IsTrusted Is it credible?
 * @property string SignedData Signed data
 * @property mixed SaltPrefix Salt for better security (inserted before data)
 * @property mixed SaltSuffix Salt for better security (inserted after data)
 */
class SignedData
{

    private $unsignedData = null;
    private $isTrusted = null;
    private $signedData = null;
    private $saltPrefix;
    private $saltSuffix;

    public static $ALLOW_UNTRUSTED_DATA = false;

    const SIGNATURE_LENGTH = Hash::B64SHA1length;

    /**
     * Creates empty instance
     *
     * @param mixed $saltPrefix Salt for better security (inserted before data)
     * @param mixed $saltSuffix Salt for better security (inserted after data)
     */
    public function __construct($saltPrefix = null, $saltSuffix = null)
    {
        $this->setSaltPrefix($saltPrefix);
        $this->setSaltSuffix($saltSuffix);
    }

    /**
     * Returns property value by name
     *
     * @param string $name Property name
     * @return mixed Property value
     * @throws \Exception If couldn't find property.
     */
    public function __get($name)
    {
        switch ($name) {
            case "UnsignedData":
                return $this->getUnsignedData();
            case "SignedData":
                return $this->signedData;
            case "SaltPrefix":
                return $this->saltPrefix;
            case "SaltSuffix":
                return $this->saltSuffix;
            case "IsTrusted":
                return $this->isTrusted;
            default:
                throw new SignedDataException("Variable $" . $name . " not found.");
                break;
        }
    }

    /**
     * Sets property value by name
     *
     * @param string $name Property name
     * @param mixed $value Property value
     * @throws \Exception If couldn't access property.
     */
    public function __set($name, $value)
    {
        switch ($name) {
            case "UnsignedData":
                $this->setUnsignedData($value);
                break;
            case "SignedData":
                $this->setSignedData($value);
                break;
            case "SaltPrefix":
                $this->setSaltPrefix($value);
                break;
            case "SaltSuffix":
                $this->setSaltSuffix($value);
                break;
            case "IsTrusted":
                throw new SignedDataException("Variable $" . $name . " is readonly.");
                break;
            default:
                throw new SignedDataException("Variable $" . $name . " not found.");
                break;
        }
    }

    /**
     * Gets unsigned data
     *
     * @throws SignedDataException
     * @return mixed Deserialized unsigned data
     */
    private function getUnsignedData()
    {
        try {
            return unserialize($this->unsignedData);
        } catch (\Exception $e) {
            throw new SignedDataException($e->getMessage(), SignedDataException::InvalidDataException, $e);
        }
    }

    /**
     * Sets unsigned data
     *
     * This method automatically generates signed data.
     *
     * @param mixed $unsignedData Unsigned data
     * @return string Signed data
     */
    private function setUnsignedData($unsignedData)
    {
        $unsignedData = serialize($unsignedData);
        $this->unsignedData = $unsignedData;
        $unsignedData = base64_encode($unsignedData);
        $this->signedData = Hash::B64SHA1(
                base64_encode($this->saltPrefix) .
                $unsignedData .
                base64_encode($this->saltSuffix)
            ) . $unsignedData;
        $this->isTrusted = true;
        return $this->SignedData;
    }

    /**
     * Sets signed data
     *
     * This method automatically checks data, sets `IsTrusted` property and extract signed data.
     * than returns unsigned data
     *
     * @param string $signedData Signed data as Base64 string
     * @return mixed Unsigned data (if data is credible, otherwise `null`)
     */
    private function setSignedData($signedData)
    {
        $this->signedData = $signedData;
        $this->unsignedData = substr($signedData, self::SIGNATURE_LENGTH);
        $this->unsignedData = base64_decode($this->unsignedData);
        $this->isTrusted = $this->check();
        return $this->IsTrusted ? $this->UnsignedData : null;
    }

    /**
     * Sets salt (prefix)
     *
     * @param mixed $saltPrefix Salt for better security (inserted before data)
     */
    private function setSaltPrefix($saltPrefix)
    {
        $this->saltPrefix = $saltPrefix;
    }

    /**
     * Sets salt (suffix)
     *
     * @param mixed $saltSuffix Salt for better security (inserted after data)
     */
    private function setSaltSuffix($saltSuffix)
    {
        $this->saltSuffix = $saltSuffix;
    }

    /**
     * Checks credibility
     *
     * @throws SignedDataException
     * @return bool `True` if data is credible, otherwise `false`
     */
    private function check()
    {
        $new = new SignedData($this->SaltPrefix, $this->SaltSuffix);
        $new->setUnsignedData($this->UnsignedData);
        $isTrusted = ($new->SignedData == $this->SignedData);
        if (!$isTrusted && !self::$ALLOW_UNTRUSTED_DATA) {
            throw new SignedDataException("Untrusted data", SignedDataException::UntrustedDataException);
        }
        return $isTrusted;
    }

}
