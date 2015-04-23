<?php
/**
 * Created by IntelliJ IDEA.
 * User: rek
 * Date: 15/4/23
 * Time: 下午6:10
 */
include_once('../autoload.php');

use wechat\WxAES;


// 第三方发送消息给公众平台
$encodingAesKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
$token = "pamtest";
$appId = "wxb11529c136998cb6";
$text = "<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>";


$wxAES = new WxAES($encodingAesKey, $appId, $token);
$encryptedMsg = $wxAES->encode($text);
echo "加密后的消息：", $encryptedMsg, "\n";

//解密需要的timestamp、nonce、signature会优先从消息中取得，如果消息中没有，会自动从$_GET参数中取得

$decryptedMsg = $wxAES->decode($encryptedMsg);

echo "解密成功的消息：", $decryptedMsg, "\n";
