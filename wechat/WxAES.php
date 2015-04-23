<?php
/**
 * Created by IntelliJ IDEA.
 * User: rek
 * Date: 15/4/23
 * Time: 下午6:08
 */

namespace wechat;

class WxAESException extends \Exception {}

class AESErrorCode {
    const OK = 0;
    const ValidateSignatureError = -40001;
    const ParseXmlError = -40002;
    const ComputeSignatureError = -40003;
    const IllegalAesKey = -40004;
    const ValidateAppIdError = -40005;
    const EncryptAESError = -40006;
    const DecryptAESError = -40007;
    const IllegalBuffer = -40008;
    const EncodeBase64Error = -40009;
    const DecodeBase64Error = -40010;
    const GenReturnXmlError = -40011;
}

class WxAES {

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $appId;

    /**
     * @var string
     */
    private $token;

    /**
     * @var string
     */
    private $iv;

    public function __construct($key, $appId, $token) {
        $this->key = base64_decode($key.'=');
        if ($this->key === false || strlen($this->key) != 32) {
            throw new WxAESException('Illegal AES Key', AESErrorCode::IllegalAesKey);
        }
        $this->iv = substr($this->key, 0, 16);
        $this->appId = $appId;
        $this->token = $token;
    }

    /**
     * @param string $originalXML 原始的XML消息
     * @return string 符合微信格式的加密的XML
     * @throws WxAESException
     */
    public function encode($originalXML) {

        //真搞不懂腾讯在加密数据前面写16字节的随机串的目的是什么
        $toEncodeData = openssl_random_pseudo_bytes(16) . pack('N', strlen($originalXML)) . $originalXML . $this->appId;

        // 本来openssl函数可以自己加入补位的，可是腾讯用了自定义的补位长度，所以只好再实现一遍了
        $toEncodeData = $this->pkcs7pad($toEncodeData, 32);
        $encoded = openssl_encrypt($toEncodeData, 'AES-256-CBC', $this->key, OPENSSL_ZERO_PADDING, substr($this->key, 0, 16));

        if ($encoded === false) {
            throw new WxAESException('Encrypt AES Error', AESErrorCode::EncryptAESError);
        }

        $timestamp = time();
        $nonce = rand(100000000, 999999999);
        $signature = $this->signature($timestamp, $nonce, $encoded);

        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<xml><Encrypt><![CDATA[$encoded]]></Encrypt><MsgSignature><![CDATA[$signature]]></MsgSignature><TimeStamp>$timestamp</TimeStamp><Nonce><![CDATA[$nonce]]></Nonce></xml>\r\n";
    }

    public function decode($encryptedXML) {
        $stack = new \SplStack();
        $arr = array();
        $x = xml_parser_create('UTF-8');
        //考虑到PHP5.4以上版本才能用不补位的openssl函数，所以闭包是一定可以支持的。
        xml_set_element_handler($x, function($x, $name) use ($stack) {
            $stack->push($name);
        }, function() use ($stack) {
            $stack->pop();
        });
        xml_set_character_data_handler($x, function($x, $data) use (&$arr, $stack) {
            $name = strtolower($stack->top());
            $arr[$name] = $data;
        });
        if (!xml_parse($x, $encryptedXML, true)) {
            throw new WxAESException('Parse XML Error', AESErrorCode::ParseXmlError);
        }
        xml_parser_free($x);
        if (!isset($arr['encrypt'])) {
            return $encryptedXML;
        }

        $encrypt = $arr['encrypt'];
        $nonce = isset($arr['nonce'])?$arr['nonce']:$_GET['nonce'];
        $timestamp = isset($arr['timestamp'])?$arr['timestamp']:$_GET['timestamp'];
        $msgSignature = isset($arr['msgsignature'])?$arr['msgsignature']:$_GET['msg_signature'];

        $signature = $this->signature($timestamp, $nonce, $encrypt);
        if ($msgSignature !== $signature) {
            throw new WxAESException('Validate Signature Error', AESErrorCode::ValidateSignatureError);
        }
        $decrypt = openssl_decrypt($encrypt, 'AES-256-CBC', $this->key, OPENSSL_ZERO_PADDING, substr($this->key, 0, 16));

        if ($decrypt === false) {
            throw new WxAESException('Decrypt AES Error', AESErrorCode::DecryptAESError);
        }
        $decrypt = $this->pkcs7unpad($decrypt, 32);

        $content = substr($decrypt, 16);
        $len = unpack("N", substr($content, 0, 4));
        $len = $len[1];
        $xml = substr($content, 4, $len);
        $fromAppId = substr($content, $len + 4);

        if ($fromAppId !== $this->appId) {
            throw new WxAESException('Validate AppId Error', AESErrorCode::ValidateAppIdError);
        }

        return $xml;
    }

    private function pkcs7pad($str, $blockSize=16) {
        $padLen = $blockSize - strlen($str) % $blockSize;
        return $str . str_repeat(chr($padLen), $padLen);
    }

    private function pkcs7unpad($str, $blockSize=16) {
        $padLen = ord(substr($str, -1));
        if ($padLen < 1 || $padLen > $blockSize) {
            return $str;
        }
        return substr($str, 0, -$padLen);
    }

    private function signature($timestamp, $nonce, $data) {
        $a = [$this->token, $timestamp, $nonce, $data];
        sort($a, SORT_STRING);
        return sha1(implode('', $a));
    }
}
