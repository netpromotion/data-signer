<?php namespace PetrKnap\Utils\Security;
/**
 * Static class that provides methods for calculating the hash fingerprints and random salts
 *
 * Methods prefixed with `B64` returns the Base64-encoded output. The length of B64 output can be get from constant
 * named as `{function name}length`, f.e. `B64SHA512length`.
 *
 * @author   Petr Knap <dev@petrknap.cz>
 * @since    2012-04-15
 * @category Security
 * @package  PetrKnap\Utils\Security
 * @version  1.0
 * @license  https://github.com/petrknap/utils/blob/master/LICENSE MIT
 * @homepage http://dev.petrknap.cz/Security/Hash.php.html
 * @see      http://www.aspnet.cz/articles/93-uchovavani-hesel-ve-webovych-aplikacich
 * @example  HashTest.php Test cases
 *
 * @change 1.0 Removed backward compatibility with alpha versions 0.*
 * @change 0.7 Changed licensing from "MS-PL":[http://opensource.org/licenses/ms-pl.html] to "MIT":[https://github.com/petrknap/utils/blob/master/LICENSE]
 * @change 0.7 Moved to `PetrKnap\Utils\Security`
 * @change 0.7 Fully translated PhpDoc
 * @change 0.6 Added support for URL like B64 outputs
 * @change 0.6 Added method `B642URL`:[#method_B642URL]
 * @change 0.6 Added method `URL2B64`:[#method_URL2B64]
 * @change 0.5 Added support for SHA256, SHA384 and SHA512
 * @change 0.4 Added method `RandomBytes`:[#method_RandomBytes]
 */
class Hash {

    /**
     * Length of B64 output from `B64SHA512`:[#method_B64SHA512]
     */
    const B64SHA512length = 86;

    /**
     * Length of B64 output from `B64SHA384`:[#method_B64SHA384]
     */
    const B64SHA384length = 64;

    /**
     * Length of B64 output from `B64SHA256`:[#method_B64SHA256]
     */
    const B64SHA256length = 43;

    /**
     * Length of B64 output from `B64SHA1`:[#method_B64SHA1]
     */
    const B64SHA1length = 27;

    /**
     * Length of B64 output from `B64MD5`:[#method_B64MD5]
     */
    const B64MD5length = 22;

    /**
     * Returns SHA512 fingerprint in B64
     *
     * @param mixed $input Input data
     * @return string Fingerprint in B64
     */
    public static function B64SHA512($input) {
        return substr(base64_encode(hash("sha512", $input, true)), 0, self::B64SHA512length);
    }

    /**
     * Returns SHA384 fingerprint in B64
     *
     * @param mixed $input Input data
     * @return string Fingerprint in B64
     */
    public static function B64SHA384($input) {
        return substr(base64_encode(hash("sha384", $input, true)), 0, self::B64SHA384length);
    }

    /**
     * Returns SHA256 fingerprint in B64
     *
     * @param mixed $input Input data
     * @return string Fingerprint in B64
     */
    public static function B64SHA256($input) {
        return substr(base64_encode(hash("sha256", $input, true)), 0, self::B64SHA256length);
    }

    /**
     * Returns SHA1 fingerprint in B64
     *
     * @param mixed $input Input data
     * @return string Fingerprint in B64
     */
    public static function B64SHA1($input)
    {
        return substr(base64_encode(sha1($input, true)), 0, self::B64SHA1length);
    }

    /**
     * Returns MD5 fingerprint in B64
     *
     * @param mixed $input Input data
     * @return string fingerprint in B64
     */
    public static function B64MD5($input)
    {
        return substr(base64_encode(md5($input, true)), 0, self::B64MD5length);
    }

    /**
     * Returns random set of bytes in HEX
     *
     * @param int $n Length of set in bytes
     * @return string Random set of bytes in HEX
     */
    public static function RandomBytes($n) {
        $out = "";
        $mem = array(0,0);
        for($i = 0; $i < $n; $i++)
        {
            $mem[0] = rand(0,100);
            $out .= dechex($mem[0]%16);
            usleep(50);
            $mem[1] = rand(0,100);
            if($mem[0] == $mem[1]) $mem[1]++;
            $out .= dechex($mem[1]%16);
            usleep(25);
        }
        return strtoupper($out);
    }

    /**
     * Converts B64 into URL friendly B64 and vice versa
     *
     * @param string $input Input data
     * @param bool $decode Is input URL friendly B64?
     * @return string Output data
     */
    private static function B64URLConverter($input, $decode)
    {
        $replaceE = array("+" => "-", "/" => "_");
        $replaceD = array("-" => "+", "_" => "/");
        $c = 0;
        if(!$decode) {
            $output = "B64_";
            $output.= strtr($input, $replaceE);
            $tmp = strlen($output);
            for($i=3; $i > 0; $i--)
            {
                if($output[$tmp-$i] == '=') $c++;
            }
            if($c > 0)
            $output = substr($output, 0, -$c);
            $output.=$c;
        }
        else {
            $c   = substr($input,   -1);
            $output = substr($input, 4,-1);
            for($i=0; $i < $c; $i++) $output .= '=';
            $output = strtr($output, $replaceD);
        }
        return $output;
    }

    /**
     * Converts B64 into URL friendly B64
     *
     * @param string $B64 Data as B64
     * @return string URL friendly B64
     */
    public static function B642URL($B64) {
        return self::B64URLConverter($B64, false);
    }

    /**
     * Converts URL friendly B64 into B64
     *
     * @param string $URL URL friendly B64
     * @return string Data as B64
     */
    public static function URL2B64($URL) {
        return self::B64URLConverter($URL, true);
    }

}
