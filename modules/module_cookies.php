<?php
/**
 * This file is a part of the CIDRAM package.
 * Homepage: https://cidram.github.io/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: Optional cookie scanner module (last modified: 2021.10.15).
 *
 * False positive risk (an approximate, rough estimate only): « [x]Low [ ]Medium [ ]High »
 *
 * Many thanks to Michael Hopkins, the creator of ZB Block (GNU/GPLv2) and its
 * cookie scanner module, which the cookie scanner module for CIDRAM is based
 * upon and inspired by.
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM') && !defined('CIDRAM-L')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Safety. */
if (!isset($CIDRAM['ModuleResCache'])) {
    $CIDRAM['ModuleResCache'] = [];
}

/** Defining as closure for later recall (no params; no return value). */
$CIDRAM['ModuleResCache'][$Module] = function () use (&$CIDRAM) {
    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Count cookies. */
    $Cookies = count($_COOKIE);

    /** Guard and protection against flooding. */
    if (!$Cookies || $Trigger($Cookies > 30, 'Cookie flood', 'Cookie flood detected!')) {
        return;
    }

    /** Signatures start from here. */
    foreach ($_COOKIE as $Key => $Value) {
        /** MyBB fix (skip iteration if value/key are unexpected types). */
        if (is_array($Key) || is_array($Value) || is_object($Key) || is_object($Value)) {
            continue;
        }

        $KeyLC = strtolower($Key);
        $ValueLC = strtolower($Value);
        $ThisPair = $Key . '->' . $Value;
        $ThisPairN = preg_replace('/\s/', '', strtolower($ThisPair));

        $Trigger(preg_match('/(?:\+A(?:CI|D[sw4]|[FH][s0]|GA)-|U\+003[EC])/', $ThisPair), 'UTF-7 entities detected in cookie'); // 2017.01.02

        $Trigger(preg_match('/\((?:["\']{2})?\)/', $ThisPairN), 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(preg_match(
            '/(?:_once|able|as(c|hes|sert)|c(hr|ode|ontents)|e(cho|regi|scape|va' .
            'l)|ex(ec|ists)?|f(ile|late|unction)|hex2bin|get(c|csv|ss?)?|i(f|ncl' .
            'ude)|len(gth)?|nt|open|p(ress|lace|lode|uts)|print(f|_r)?|re(ad|pla' .
            'ce|quire|store)|rot13|s(tart|ystem)|w(hil|rit)e)["\':(\[{<$]/i',
            $ThisPairN
        ), 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(
            preg_match('/\$(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))/', $ThisPairN),
            'Command injection detected in cookie'
        ); // 2017.01.20
        $Trigger(preg_match('/add(?:handler|type|inputfilter)/', $ThisPairN), 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/http_(?:cmd|sum)/', $ThisPairN), 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/pa(?:rse_ini_file|ssthru)/', $ThisPairN), 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/rewrite(?:cond|rule)/', $ThisPairN), 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(preg_match('/set(?:handl|inputfilt)er/', $ThisPairN), 'Command injection detected in cookie'); // 2017.01.20
        $Trigger(preg_match('/u(?:nserializ|ploadedfil)e/', $ThisPairN), 'Command injection detected in cookie'); // 2017.01.20
        $Trigger(strpos($ThisPairN, '$http_raw_post_data') !== false, 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'dotnet_load') !== false, 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'execcgi') !== false, 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'forcetype') !== false, 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'move_uploaded_file') !== false, 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'symlink') !== false, 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(strpos($ThisPairN, 'tmp_name') !== false, 'Command injection detected in cookie'); // 2017.01.02
        $Trigger(strpos($ThisPairN, '_contents') !== false, 'Command injection detected in cookie'); // 2017.01.02

        $Trigger(preg_match('/ap(?:ache_[\w\d_]{4,16}|c_[\w\d_]{3,16})\(/', $ThisPairN), 'Function call detected in cookie'); // 2018.06.24
        $Trigger(preg_match('/curl_[\w\d_]{4,10}\(/', $ThisPairN), 'Function call detected in cookie'); // 2018.06.24
        $Trigger(preg_match('/ftp_[\w\d_]{3,7}\(/', $ThisPairN), 'Function call detected in cookie'); // 2018.06.24
        $Trigger(preg_match('/mysqli?(?:_|\:\:)[\w\d_]{4,9}\(/', $ThisPairN), 'Function call detected in cookie'); // 2018.06.24
        $Trigger(preg_match('/phpads_[\w\d_]{4,12}\(/', $ThisPairN), 'Function call detected in cookie'); // 2018.06.24
        $Trigger(preg_match('/posix_[\w\d_]{4,19}\(/', $ThisPairN), 'Function call detected in cookie'); // 2018.06.24
        $Trigger(preg_match('/proc_[\w\d_]{4,10}\(/', $ThisPairN), 'Function call detected in cookie'); // 2018.06.24

        $Trigger(preg_match('/\'(?:uploadedfile|move_uploaded_file|tmp_name)\'/', $ThisPairN), 'Probe attempt'); // 2017.01.02

        $Trigger($Key === 'SESSUNIVUCADIACOOKIE', 'Hotlinking detected', 'Hotlinking not allowed!'); // 2017.01.02

        $Trigger($Key === 'arp_scroll_position' && strpos($ThisPairN, '400') !== false, 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'BALANCEID' && strpos($ThisPairN, 'balancer.') !== false, 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'BX', 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'ja_edenite_tpl', 'Bad cookie'); // 2017.01.02
        $Trigger($Key === 'phpbb3_1fh61_', 'Bad cookie'); // 2017.01.02

        $Trigger((
            ($Key === 'CUSTOMER' || $Key === 'CUSTOMER_INFO' || $Key === 'NEWMESSAGE') &&
            strpos($ThisPairN, 'deleted') !== false
        ), 'Cookie hack detected'); // 2017.01.02

        /** These signatures can set extended tracking options. */
        if (
            $Trigger(strpos($ThisPairN, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempted via cookies') || // 2017.01.02
            $Trigger(strpos($ThisPairN, 'linkirc') !== false, 'Shell upload attempted via cookies') || // 2017.01.02
            $Trigger($Key === '()' || $Value === '()', 'Cookie hack detected (Bash/Shellshock)') || // 2017.01.02
            $Trigger($KeyLC === 'rm ' . '-rf' || $ValueLC === 'rm ' . '-rf', 'Cookie hack detected') || // 2017.01.02
            $Trigger(preg_match('/:(?:\{\w:|[\w\d][;:]\})/', $ThisPairN), 'Cookie hack detected') || // 2018.06.24
            $Trigger((
                ($Value === -1 || $Value === '-1') &&
                ($Key === 'ASP_NET_SessionId' || $Key === 'CID' || $Key === 'SID' || $Key === 'NID')
            ), 'ASP.NET hack detected') // 2017.01.02
        ) {
            $CIDRAM['Tracking options override'] = 'extended';
        }
    }

    /** Reporting. */
    if (!empty($CIDRAM['BlockInfo']['IPAddr'])) {
        if (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Function call detected in cookie') !== false) {
            $CIDRAM['Reporter']->report([15], ['Function call detected in cookie.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Command injection detected in cookie') !== false) {
            $CIDRAM['Reporter']->report([15], ['Command injection detected in cookie.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Cookie hack detected') !== false) {
            $CIDRAM['Reporter']->report([15], ['Cookie hack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Shell upload attempted via cookies') !== false) {
            $CIDRAM['Reporter']->report([15], ['Shell upload attempted via cookies.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Probe attempt') !== false) {
            $CIDRAM['Reporter']->report([21], ['Probe attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        }
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
