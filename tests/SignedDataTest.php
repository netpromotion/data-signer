<?php

use PetrKnap\Utils\Security\SignedData;
use PetrKnap\Utils\Security\SignedDataException;

class SignedDataTest extends PHPUnit_Framework_TestCase
{
    const data = 0x1, saltPrefix = 0x2, saltSuffix = 0x3;

    private function signedData_test($data, $saltPrefix, $saltSuffix)
    {
        SignedData::$ALLOW_UNTRUSTED_DATA = false;

        $A = new SignedData($saltPrefix, $saltSuffix);
        $A->UnsignedData = $data;

        // All is OK
        $B = new SignedData($saltPrefix, $saltSuffix);
        $B->SignedData = $A->SignedData;

        $this->assertTrue($B->IsTrusted);
        $this->assertEquals($data, $B->UnsignedData);

        // Invalid salt
        $C = new SignedData($saltSuffix, $saltPrefix);
        try {
            $C->SignedData = $A->SignedData;
            if($saltPrefix != $saltSuffix) {
                $this->fail("Invalid salt doesn't throw exception.");
            }
            else {
                $this->assertTrue($C->IsTrusted);
                $this->assertEquals($data, $C->UnsignedData);
            }
        } catch(SignedDataException $sde) {
            $this->assertEquals(SignedDataException::UntrustedDataException, $sde->getCode());
        }

        // Invalid data
        $D = new SignedData($saltPrefix, $saltSuffix);
        try {
            $lastChar = substr($A->SignedData, -1, 1);
            $D->SignedData = substr($A->SignedData, 0, -1) . $lastChar == "a" ? "b" : "a";
            $this->fail("Invalid data doesn't throw exception.");
        } catch(SignedDataException $sde) {
            $this->assertEquals(SignedDataException::UntrustedDataException, $sde->getCode());
        }

        // Invalid signature
        $E = new SignedData($saltPrefix, $saltSuffix);
        try {
            $firstChar = substr($A->SignedData, 0, 1);
            $E->SignedData = $firstChar == "a" ? "b" : "a" . substr($A->SignedData, 1);
            $this->fail("Invalid signature doesn't throw exception.");
        } catch(SignedDataException $sde) {
            $this->assertEquals(SignedDataException::UntrustedDataException, $sde->getCode());
        }

    }

    public function test_simple() {
        $this->signedData_test(self::data, self::saltPrefix, self::saltSuffix);
    }

    public function test_mixedData() {
        $data = array(
            "string",
            array("array"),
            array("ar" => "ray"),
            0x1234567890abcdef,
            012345670,
            0b10,
            new SignedData(self::saltPrefix, self::saltSuffix),
            null
        );
        foreach($data as $d) {
            $this->signedData_test($d, self::saltPrefix, self::saltSuffix);
        }
    }

    public function test_mixedSalt() {
        $salt = array(
            "string",
            0x1234567890abcdef,
            012345670,
            0b10,
            null,
        );
        foreach($salt as $a) {
            foreach($salt as $b) {
                $this->signedData_test(self::data, $a, $b);
            }
        }
    }

    public function test_outputSize() {
        $sd = new SignedData();

        for($i = 0, $data = "string"; $i < 10; $i++, $data .= $data) {
            $sd->UnsignedData = $data;
            $expectedSize = strlen($data);
            $expectedSize = $expectedSize > SignedData::SIGNATURE_LENGTH ? $expectedSize : SignedData::SIGNATURE_LENGTH;
            $expectedSize *= 1.66;
            $this->assertLessThanOrEqual($expectedSize + SignedData::SIGNATURE_LENGTH, strlen($sd->SignedData));
        }

    }
}
