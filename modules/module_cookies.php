<?php
/**
 * This file is a part of the CIDRAM package, and can be downloaded for free
 * from {@link https://github.com/Maikuolan/CIDRAM/ GitHub}.
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: Optional cookie scanner module (last modified: 2017.01.05).
 *
 * Many thanks to Michael Hopkins, the creator of ZB Block (GNU/GPLv2) and its
 * cookie scanner module, which the cookie scanner module for CIDRAM is based
 * upon and inspired by.
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Required for handling all signature triggers in this file. */
$Trigger = function ($Condition, $ReasonShort, $ReasonLong = '', $DefineOptions = array()) use (&$CIDRAM) {
    if (!$Condition) {
        return false;
    }
    if (!$ReasonLong) {
        $ReasonLong = $CIDRAM['lang']['denied'];
    }
    if (is_array($DefineOptions) && !empty($DefineOptions)) {
        while (($Cat = each($DefineOptions)) !== false) {
            while (($Option = each($Cat[1])) !== false) {
                $CIDRAM['Config'][$Cat[0]][$Option[0]] = $Option[1];
            }
        }
    }
    $CIDRAM['BlockInfo']['ReasonMessage'] = $ReasonLong;
    if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
        $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
    }
    $CIDRAM['BlockInfo']['WhyReason'] .= $ReasonShort;
    if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
        $CIDRAM['BlockInfo']['Signatures'] .= ', ';
    }
    $Debug = debug_backtrace(DEBUG_BACKTRACE_PROVIDE_OBJECT | DEBUG_BACKTRACE_IGNORE_ARGS, 1)[0];
    $CIDRAM['BlockInfo']['Signatures'] .= basename($Debug['file']) . ':L' . $Debug['line'];
    $CIDRAM['BlockInfo']['SignatureCount']++;
    return true;
};

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 999). */
$InstaBan = array('Options' => array('TrackTime' => 31536000, 'TrackCount' => 999));

$Cookies = count($_COOKIE);

/** Signatures start from here. */
if (!$Trigger($Cookies > 30, 'Cookie flood', 'Cookie flood detected!') && $Cookies) {
    array_walk($_COOKIE, function($Value, $Key) use (&$CIDRAM, &$Trigger, &$InstaBan) {
        $KeyLC = strtolower($Key);
        $ValueLC = strtolower($Value);
        $ThisPair = $Key . '->' . $Value;
        $ThisPairN = preg_replace('/\s/', '', strtolower($ThisPair));

        $Trigger(preg_match('/(?:\+A(?:CI|D[sw4]|[FH][s0]|GA)-|U\+003[EC])/', $ThisPair), 'UTF-7 entities detected in cookie'); // 2017.01.02

        $Trigger(preg_match('/\((?:["\']{2})?\)/', $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(preg_match(
            '/(?:_once|able|as(c|hes|sert)|c(hr|ode|ontents)|e(cho|regi|scape|va' .
            'l)|ex(ec|ists)?|f(ile|late|unction)|hex2bin|get(c|csv|ss?)?|i(f|ncl' .
            'ude)|len(gth)?|nt|open|p(ress|lace|lode|uts)|print(f|_r)?|re(ad|pla' .
            'ce|quire|store)|rot13|s(tart|ystem)|w(hile|rite))["\':(\[{<$]/i',
        $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(
            preg_match('/\$(?:globals|_cookie|_env|_files|_get|_post|_request|_server|_session)/i', $ThisPairN),
            'Command injection'
        ); // 2017.01.02
        $Trigger(preg_match('/add(?:handler|type|inputfilter)/', $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(preg_match('/http_(?:cmd|sum)/', $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(preg_match('/pa(?:rse_ini_file|ssthru)/', $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(preg_match('/rewrite(?:cond|rule)/', $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(preg_match('/set(?:handler|inputfilter)/', $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(preg_match('/u(?:nserialize|ploadedfile)/', $ThisPairN), 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, '$http_raw_post_data') !== false, 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'dotnet_load') !== false, 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'execcgi') !== false, 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'forcetype') !== false, 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'move_uploaded_file') !== false, 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'symlink') !== false, 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'tmp_name') !== false, 'Command injection'); // 2017.01.02
        $Trigger(strpos($ThisPairN, '_contents') !== false, 'Command injection'); // 2017.01.02

        $Trigger(preg_match('/ap(?:ache_[a-z0-9_]{4,16}|c_[a-z0-9_]{3,16})\(/', $ThisPairN), 'Function call detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/curl_[a-z0-9_]{4,10}\(/', $ThisPairN), 'Function call detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/ftp_[a-z0-9_]{3,7}\(/', $ThisPairN), 'Function call detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/mysqli?(?:_|\:\:)[a-z0-9_]{4,9}\(/', $ThisPairN), 'Function call detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/phpads_[a-z0-9_]{4,12}\(/', $ThisPairN), 'Function call detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/posix_[a-z0-9_]{4,19}\(/', $ThisPairN), 'Function call detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/proc_[a-z0-9_]{4,10}\(/', $ThisPairN), 'Function call detected in cookie'); // 2017.01.02

        $Trigger(preg_match('/\'(?:uploadedfile|move_uploaded_file|tmp_name)\'/', $ThisPairN), 'Probe attempt'); // 2017.01.02

        $Trigger(strpos($ThisPairN, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'linkirc') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02

        $Trigger($Key === 'SESSUNIVUCADIACOOKIE', 'Hotlinking detected', 'Hotlinking not allowed!'); // 2017.01.02

        $Trigger($Key === 'arp_scroll_position' && strpos($ThisPairN, '400') !== false, 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'BALANCEID' && strpos($ThisPairN, 'balancer.') !== false, 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'BX', 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'ja_edenite_tpl', 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'phpbb3_1fh61_', 'Bad cookie'); // 2017.01.02

        $Trigger($Key === '()' || $Value === '()', 'Bash/Shellshock', '', $InstaBan); // 2017.01.02

        $Trigger((
            ($Key == 'CUSTOMER' || $Key == 'CUSTOMER_INFO' || $Key == 'NEWMESSAGE') &&
            strpos($ThisPairN, 'deleted') !== false
        ), 'Hack attempt detected'); // 2017.01.02

        $Trigger($KeyLC === 'rm ' . '-rf' || $ValueLC === 'rm ' . '-rf', 'Hack attempt detected', '', $InstaBan); // 2017.01.02

        $Trigger((
            ($Value == -1 || $Value == '-1') &&
            ($Key == 'ASP_NET_SessionId' || $Key == 'CID' || $Key == 'SID' || $Key == 'NID')
        ), 'ASP.NET hack detected', '', $InstaBan); // 2017.01.02

    });
}
