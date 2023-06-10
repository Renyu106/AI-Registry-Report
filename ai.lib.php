<?php
require_once 'GoogleAuthenticator.php';
$GOOGLE_AUTH = new GoogleAuthenticator();

$ENDPOINT = "https://epp.whois.ai";
$GOOGLE_OTP_KEY = "##GOOGLE_2FA_KEY##";
$ID = "##ACCOUNT_ID##";
$PW = "##ACCOUNT_PW##";


function EXTRACT_TEXT($CONTENT, $START_STRING, $SEND_STRING, $REPLACE=array()){
    $PROCESS = explode($START_STRING,$CONTENT);
    $PROCESS = $PROCESS[1];
    $PROCESS = explode($SEND_STRING,$PROCESS);
    $PROCESS = $PROCESS[0];
    $PROCESS = trim($PROCESS);
    foreach ($REPLACE as $KEY => $VALUE) {
        $PROCESS = str_replace($KEY, $VALUE, $PROCESS);
    }
    return $PROCESS;
}

function CURL($METHOD = "POST", $URL, $GET_HEADER = false, $DATA = array(), $HEADER = array())
{
    $CURL = curl_init();
    curl_setopt($CURL, CURLOPT_URL, $URL);
    curl_setopt($CURL, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($CURL, CURLOPT_CUSTOMREQUEST, $METHOD);
    curl_setopt($CURL, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($CURL, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($CURL, CURLOPT_POSTFIELDS, $DATA);
    if ($GET_HEADER) curl_setopt($CURL, CURLOPT_HEADER, 1);

    if (empty($HEADER)) $HEADER = array();
    curl_setopt($CURL, CURLOPT_HTTPHEADER, $HEADER);
    $RESPONSE = curl_exec($CURL);
    curl_close($CURL);

    if ($GET_HEADER) {
        $headerSize = curl_getinfo($CURL, CURLINFO_HEADER_SIZE);
        $header = substr($RESPONSE, 0, $headerSize);
        $body = substr($RESPONSE, $headerSize);
        return array("HEADER" => $header, "BODY" => $body);
    } else {
        return $RESPONSE;
    }
}

function CURL_LOGIN($ID, $PW, $CAPTCHA, $CAPTCHA_ID){
    global $ENDPOINT;
    $curl = curl_init();
    curl_setopt_array($curl, array(
            CURLOPT_URL => "{$ENDPOINT}/j_security_check",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => 'j_uri=%2Findex.jsp&j_username='.$ID.'&j_password='.$PW.'&mypw='.$CAPTCHA.'&jcaptcha_id='.$CAPTCHA_ID.'&submit=Log%2Bin',
            CURLOPT_HTTPHEADER => array(
                    'Cookie: SSL_JSESSIONID='.$CAPTCHA_ID,
                    'Content-Type: application/x-www-form-urlencoded'
            ),
    ));
    $response = curl_exec($curl);
    curl_close($curl);
    return $response;
}

function CURL_2FA_LOGIN($GET_2FA_CODE, $CAPTCHA_ID)
{
    global $ENDPOINT;
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => "{$ENDPOINT}/login_2fa.jsp",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_HEADER => true,
        CURLOPT_POSTFIELDS => 'token='.$GET_2FA_CODE.'&submit=Authenticate',
        CURLOPT_HTTPHEADER => array(
            'Cookie: SSL_JSESSIONID='.$CAPTCHA_ID,
            'Content-Type: application/x-www-form-urlencoded'
        ),
    ));
    $response = curl_exec($curl);
    curl_close($curl);
    return $response;
}

// 캡챠 이미지 받기
$CAPTCHA = CURL("GET", "{$ENDPOINT}/simpleCaptcha?type=LOGIN&name=_site", true, array(
    "type" => "LOGIN",
    "name" => "_site",
), array());
$CAPTCHA_BODY = $CAPTCHA["BODY"];
$CAPTCHA_STR = explode("\r\n\r\n", $CAPTCHA_BODY);

// 캡챠 이미지 저장
$CAPTCHA_IMG = $CAPTCHA_STR[1];
file_put_contents("captcha.png", $CAPTCHA_IMG);

# 캡챠 쿠키 저장
$CAPTCHA_HEADER = $CAPTCHA_STR[0];
$COOKIE = EXTRACT_TEXT($CAPTCHA_HEADER, 'Set-Cookie: ', ';');
echo "COOKIE : ".$COOKIE."\n";

// 캡챠 입력 받기
echo "현재 위치에 저장된 captcha.png를 확인해주세요 : ";
$INPUT_CAPTCHA = strtoupper(trim(fgets(STDIN)));
// echo "입력된 캡챠 : ".$INPUT_CAPTCHA."\n";

// 캡챠 아이디
$CAPTCHA_ID_STR = explode("=", $COOKIE);
$CAPTCHA_ID = $CAPTCHA_ID_STR[1];
echo "캡챠 ID : ".$CAPTCHA_ID."\n";

// 로그인후
$CURL_LOGIN = CURL_LOGIN($ID, $PW, $INPUT_CAPTCHA, $CAPTCHA_ID);
$GET_2FA_CODE = $GOOGLE_AUTH->getCode($GOOGLE_OTP_KEY);
echo "2차인증 코드 : $GET_2FA_CODE\n";

// 2차 인증
$CURL_2FA_LOGIN = CURL_2FA_LOGIN($GET_2FA_CODE, $CAPTCHA_ID);
$CURRENT_LOGIN_ID = EXTRACT_TEXT($CURL_2FA_LOGIN, 'username=', '"');
if(empty($CURRENT_LOGIN_ID)) exit("로그인 실패\n");
echo "로그인 ID : ".$CURRENT_LOGIN_ID."\n";

// 리스트 KEY 추출
$GET_LIST_KEY = CURL("GET", "{$ENDPOINT}/domains/list.jsp", false, array(), array(
    "Cookie: SSL_JSESSIONID=".$CAPTCHA_ID,
));
$LIST_KEY = EXTRACT_TEXT($GET_LIST_KEY, 'var url = \'/domains.csv?name=Domains.csv&key=', '&cache_name=domain_cache&qt=EXPANDED_CSV');
echo "LIST KEY : ".$LIST_KEY."\n";

// 리스트 다운로드
$GET_LIST = CURL("GET", "{$ENDPOINT}/domains.csv?name=Domains.csv&key=".$LIST_KEY."&cache_name=domain_cache&qt=EXPANDED_CSV", false, array(), array(
    "Cookie: SSL_JSESSIONID=".$CAPTCHA_ID,
));
file_put_contents("list.csv", $GET_LIST);
unlink("captcha.png");
