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
 * This file: Optional security extras module (last modified: 2021.06.28).
 *
 * False positive risk (an approximate, rough estimate only): « [ ]Low [x]Medium [ ]High »
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM') && !defined('CIDRAM-L')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Safety. */
if (!isset($CIDRAM['ModuleResCache'])) {
    $CIDRAM['ModuleResCache'] = [];
}

/**
 * Defining as closure for later recall (one param; no return value).
 *
 * @param int $Infractions The number of infractions incurred thus far.
 */
$CIDRAM['ModuleResCache'][$Module] = function ($Infractions = 0) use (&$CIDRAM) {
    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    $Trigger(count($_REQUEST) >= 500, 'Hack attempt', 'Too many request variables sent!'); // 2017.01.01

    /** Needed for some bypasses specific to WordPress (detects whether we're running as a WordPress plugin). */
    $is_WP_plugin = (defined('ABSPATH') || strtolower(str_replace("\\", '/', substr(__DIR__, -31))) === 'wp-content/plugins/cidram/vault');

    /** If enabled, block empty user agents. */
    if ($CIDRAM['Config']['extras']['block_empty_ua']) {
        $Trigger(preg_replace('~[^\w\d]~i', '', $CIDRAM['BlockInfo']['UA']) === '', 'Empty UA');
    }

    /** Inherit bypass closure (see functions.php). */
    $Bypass = $CIDRAM['Bypass'];

    /**
     * Signatures based on the reconstructed URI start from here.
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if ($CIDRAM['Config']['extras']['ruri'] && $CIDRAM['BlockInfo']['rURI']) {
        $LCNrURI = str_replace("\\", '/', strtolower($CIDRAM['BlockInfo']['rURI']));

        /** Directory traversal protection. */
        $Trigger(preg_match('~(?:/|%5[cf])\.{2,}(?:/|%5[cf])~i', $LCNrURI), 'Traversal attack'); // 2017.01.13

        /** Detect bad/dangerous/malformed requests. */
        $Trigger(preg_match('~(?:(/|%5[cf])\.(/|%5[cf])|(/|%5[cf]){3,}|[\x00-\x1f\x7f])~i', $LCNrURI), 'Bad request'); // 2017.01.13

        /** WordPress user enumeration (modified 2019.09.14). */
        if ($Trigger(preg_match('~author=\d+~i', $LCNrURI), 'WordPress user enumeration not allowed')) {
            $Bypass(
                strpos($LCNrURI, 'administrator/') !== false,
                'Joomla image inserting tool bypass (WordPress user enumeration conflict)'
            ) || $Bypass(
                strpos($LCNrURI, 'search.php?keywords=') !== false,
                'phpBB search bypass (WordPress user enumeration conflict)'
            );
        }

        $Trigger((
            strpos($LCNrURI, 'wp-print.php?script=1') !== false || // 2017.10.07
            strpos($LCNrURI, 'css/newgolden.php') !== false // 2017.10.07
        ), 'WP hack attempt');

        /** WSO is a common PHP backdoor/trojan. */
        $Trigger(preg_match('~[\x5c/]wso\.php~i', $LCNrURI), 'WSO not allowed'); // 2017.03.22

        $Trigger(preg_match('~\.(?:bak|cgi|php)\.suspected~i', $LCNrURI), 'Accessing quarantined files not allowed'); // 2017.03.22

        /** These signatures can set extended tracking options. */
        if (
            $Trigger(preg_match('~(?:/%e2%80%a6x|shrift)\.php|/get?(?:fwversion|mac)~', $LCNrURI), 'Hack attempt') // 2017.02.25 mod 2021.06.28
        ) {
            $CIDRAM['Tracking options override'] = 'extended';
        }
    }

    /**
     * Query-based signatures start from here.
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if ($CIDRAM['Config']['extras']['query'] && !empty($_SERVER['QUERY_STRING'])) {
        $Query = str_replace("\\", '/', strtolower(urldecode($_SERVER['QUERY_STRING'])));
        $QueryNoSpace = preg_replace('/\s/', '', $Query);

        $Trigger(preg_match('/\((?:["\']{2})?\)/', $QueryNoSpace), 'Query command injection'); // 2016.12.31

        $Trigger(preg_match(
            '/(?:_once|able|as(?:c|hes|sert)|c(?:hr|ode|ontents)|e(?:cho|regi|sc' .
            'ape|val)|ex(?:ec|ists)?|f(?:ile|late|unction)|get(?:c|csv|ss?)?|i(?' .
            ':f|nclude)|len(?:gth)?|nt|open|p(?:ress|lace|lode|uts)|print(?:f|_r' .
            ')?|re(?:ad|place|quire|store)|rot13|s(?:tart|ystem)|w(?:hil|rit)e)[' .
            '"\':(?:\[{<$]/',
            $QueryNoSpace
        ), 'Query command injection'); // 2018.05.02

        $Trigger(preg_match(
            '/\$(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))/',
            $QueryNoSpace
        ), 'Query command injection'); // 2017.01.13

        $Trigger(preg_match('/http_(?:cmd|sum)/', $QueryNoSpace), 'Query command injection'); // 2017.01.02
        $Trigger(preg_match('/pa(?:rse_ini_file|ssthru)/', $QueryNoSpace), 'Query command injection'); // 2017.01.02
        $Trigger(preg_match('/rewrite(?:cond|rule)/', $QueryNoSpace), 'Query command injection'); // 2017.01.02
        $Trigger(preg_match('/u(?:nserializ|ploadedfil)e/', $QueryNoSpace), 'Query command injection'); // 2017.01.13
        $Trigger(strpos($QueryNoSpace, 'dotnet_load') !== false, 'Query command injection'); // 2016.12.31
        $Trigger(strpos($QueryNoSpace, 'execcgi') !== false, 'Query command injection'); // 2016.12.31
        $Trigger(strpos($QueryNoSpace, 'move_uploaded_file') !== false, 'Query command injection'); // 2016.12.31
        $Trigger(strpos($QueryNoSpace, 'symlink') !== false, 'Query command injection'); // 2016.12.31
        $Trigger(strpos($QueryNoSpace, 'tmp_name') !== false, 'Query command injection'); // 2016.12.31
        $Trigger(strpos($QueryNoSpace, '_contents') !== false, 'Query command injection'); // 2016.12.31

        $Trigger(preg_match('/%(?:0[0-8bcef]|1)/i', $_SERVER['QUERY_STRING']), 'Non-printable characters in query'); // 2016.12.31

        $Trigger(preg_match('/(?:amp(;|%3b)){2,}/', $QueryNoSpace), 'Nesting attack'); // 2016.12.31
        $Trigger(preg_match('/\?(?:&|cmd=)/', $QueryNoSpace), 'Nesting attack'); // 2017.02.25

        $Trigger((
            strpos($CIDRAM['BlockInfo']['rURI'], '/ucp.php?mode=login') === false &&
            preg_match('/%(?:(25){2,}|(25)+27)/', $_SERVER['QUERY_STRING'])
        ), 'Nesting attack'); // 2017.01.01

        $Trigger(preg_match(
            '/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/',
            $QueryNoSpace
        ), 'Query script injection'); // 2017.01.05

        $Trigger(preg_match(
            '/_(?:cookie|env|files|get|post|request|se(rver|ssion))\[/',
            $QueryNoSpace
        ), 'Query global variable hack'); // 2017.01.13

        $Trigger(strpos($QueryNoSpace, 'globals['), 'Query global variable hack'); // 2017.01.01

        $Trigger(substr($_SERVER['QUERY_STRING'], -3) === '%00', 'Null truncation attempt'); // 2016.12.31
        $Trigger(substr($_SERVER['QUERY_STRING'], -4) === '%000', 'Null truncation attempt'); // 2016.12.31
        $Trigger(substr($_SERVER['QUERY_STRING'], -5) === '%0000', 'Null truncation attempt'); // 2016.12.31

        $Trigger(preg_match('/%(?:20\'|25[01u]|[46]1%[46]e%[46]4)/', $_SERVER['QUERY_STRING']), 'Hack attempt'); // 2017.01.05
        $Trigger(preg_match('/&arrs[12]\[\]=/', $QueryNoSpace), 'Hack attempt'); // 2017.02.25
        $Trigger(preg_match('/p(?:ath|ull)\[?\]/', $QueryNoSpace), 'Hack attempt'); // 2017.01.06
        $Trigger(preg_match('/user_login,\w{4},user_(?:pass|email|activation_key)/', $QueryNoSpace), 'WP hack attempt'); // 2017.02.18
        $Trigger(preg_match('/\'%2[05]/', $_SERVER['QUERY_STRING']), 'Hack attempt'); // 2017.01.05
        $Trigger(preg_match('/\|(?:include|require)/', $QueryNoSpace), 'Hack attempt'); // 2017.01.01
        $Trigger(strpos($QueryNoSpace, "'='") !== false, 'Hack attempt'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, '.php/login.php') !== false, 'Hack attempt'); // 2017.01.05
        $Trigger(preg_match('~\dhttps?:~', $QueryNoSpace), 'Hack attempt'); // 2017.01.01 mod 2018.09.22
        $Trigger(strpos($QueryNoSpace, 'id=\'') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, 'name=lobex21.php') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, 'php://') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, 'tmunblock.cgi') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($_SERVER['QUERY_STRING'], '=-1%27') !== false, 'Hack attempt'); // 2017.01.05
        $Trigger(substr($QueryNoSpace, 0, 1) === ';', 'Hack attempt'); // 2017.01.05

        $Trigger(strpos($QueryNoSpace, 'allow_url_include=on') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'auto_prepend_file=php://input') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'cgi.force_redirect=0') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'cgi.redirect_status_env=0') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'disable_functions=""') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'open_basedir=none') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'safe_mode=off') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'suhosin.simulation=on') !== false, 'Plesk hack'); // 2017.01.05

        $Trigger(preg_match('~(?:^-|/r[ks]=|dg[cd]=1|pag(?:e|ina)=-)~', $QueryNoSpace), 'Probe attempt'); // 2017.02.25
        $Trigger(preg_match('~yt=phpinfo~', $QueryNoSpace), 'Probe attempt'); // 2017.03.05

        $Trigger(preg_match(
            '/\[(?:[alrw]\]|classes|file|itemid|l(?:astrss_ap_enabled|oadfile|ocalserverfile)|pth|src)/',
            $QueryNoSpace
        ), 'Probe attempt'); // 2017.01.17 mod 2020.11.29

        $Trigger(strpos($QueryNoSpace, '+result:') !== false, 'Spam attempt'); // 2017.01.08
        $Trigger(strpos($QueryNoSpace, 'result:+\\') !== false, 'Spam attempt'); // 2017.01.08

        $Trigger(preg_match('/(?:["\'];|[;=]\|)/', $QueryNoSpace), 'Query command injection'); // 2017.01.13
        $Trigger(preg_match('/[\'"`]sysadmin[\'"`]/', $QueryNoSpace), 'Query command injection'); // 2017.02.25
        $Trigger(preg_match('/[\'"`]\+[\'"`]/', $QueryNoSpace), 'Query command injection'); // 2017.01.03
        $Trigger(preg_match('/[\'"`]\|[\'"`]/', $QueryNoSpace), 'Pipe hack'); // 2017.01.08 mod 2017.10.31 (bugged)
        $Trigger(strpos($QueryNoSpace, 'num_replies=77777') !== false, 'Overflow attempt'); // 2017.02.25
        $Trigger(strpos($_SERVER['QUERY_STRING'], '++++') !== false, 'Overflow attempt'); // 2017.01.05
        $Trigger(strpos($_SERVER['QUERY_STRING'], '->') !== false, 'Hack attempt'); // 2017.02.25

        $Trigger(preg_match('~src=https?:~', $QueryNoSpace), 'RFI'); // 2017.02.18 mod 2018.09.22
        $Trigger(strpos($QueryNoSpace, 'path]=') !== false, 'Path hack'); // 2017.02.18

        $Trigger(strpos($QueryNoSpace, 'e9xmkgg5h6') !== false, 'Query error'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, '5889d40edd5da7597dfc6d1357d98696') !== false, 'Query error'); // 2017.02.18

        $Trigger(preg_match('/(?:keywords|query|searchword|terms)=%d8%b3%d9%83%d8%b3/', $QueryNoSpace), 'Unauthorised'); // 2017.02.18

        $Trigger(strpos($_SERVER['QUERY_STRING'], '??') !== false, 'Bad query'); // 2017.02.25
        $Trigger(strpos($_SERVER['QUERY_STRING'], ',0x') !== false, 'Bad query'); // 2017.02.25
        $Trigger(strpos($_SERVER['QUERY_STRING'], ',\'\',') !== false, 'Bad query'); // 2017.02.25

        $Trigger(preg_match('/id=.*(?:benchmark\(|id[xy]=|sleep\()/', $QueryNoSpace), 'Query SQLi'); // 2017.03.01
        $Trigger(preg_match(
            '~(?:from|union|where).*select|then.*else|(?:o[nr]|where).*is null|(?:inner|left|outer|right) join~',
            $QueryNoSpace
        ), 'Query SQLi'); // 2017.03.01 mod 2020.11.30

        $Trigger(preg_match('/cpis_.*i0seclab@intermal\.com/', $QueryNoSpace), 'Hack attempt'); // 2018.02.20

        /** These signatures can set extended tracking options. */
        if (
            $Trigger(strpos($QueryNoSpace, '$_' . '[$' . '__') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(strpos($QueryNoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(strpos($Query, 'rm ' . '-rf') !== false, 'Hack attempt') || // 2017.01.02
            $Trigger(strpos($QueryNoSpace, ';c' . 'hmod7' . '77') !== false, 'Hack attempt') || // 2017.01.05
            $Trigger(substr($QueryNoSpace, 0, 2) === '()', 'Bash/Shellshock') || // 2017.01.05
            $Trigger(strpos($QueryNoSpace, '0x31303235343830303536') !== false, 'Probe attempt') || // 2017.02.25
            $Trigger(preg_match('~(?:modez|osc|tasya)=|=(?:(?:bot|scanner|shell)z|psybnc)~', $QueryNoSpace), 'Query command injection') // 2017.02.25 mod 2021.06.28
        ) {
            $CIDRAM['Tracking options override'] = 'extended';
        }
    }

    /** If enabled, fetch the first 1MB of raw input from the input stream. */
    if ($CIDRAM['Config']['extras']['raw']) {
        $Handle = fopen('php://input', 'rb');
        $RawInput = fread($Handle, 1048576);
        fclose($Handle);
    }

    /**
     * Signatures based on raw input start from here.
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if ($CIDRAM['Config']['extras']['raw'] && $RawInput) {
        $RawInputSafe = strtolower(preg_replace('/[\s\x00-\x1f\x7f-\xff]/', '', $RawInput));

        $Trigger(
            !$is_WP_plugin && preg_match('/[\x00-\x1f\x7f-\xff"#\'-);<>\[\]]/', $RawInput),
            'Non-escaped characters in POST'
        ); // 2017.10.23

        $Trigger(preg_match('/charcode\(88,83,83\)/', $RawInputSafe), 'Hack attempt'); // 2017.03.01
        $Trigger((
            strpos($RawInputSafe, '<?xml') !== false &&
            strpos($RawInputSafe, '<!doctype') !== false &&
            strpos($RawInputSafe, '<!entity') !== false
        ), 'Suspicious request'); // 2018.07.10
        $Trigger(strpos($RawInputSafe, 'inputbody:action=update&mfbfw') !== false, 'FancyBox exploit attempt'); // 2017.03.01

        $Trigger(!$is_WP_plugin && preg_match(
            '~(?:lwp-download|fetch)ftp://|(?:fetch|lwp-download|wget)https?://|<name|method(?:call|name)|value>~i',
            $RawInputSafe
        ), 'POST RFI'); // 2018.07.10

        /** Joomla plugins update bypass (POST RFI conflict). */
        $Bypass(
            ($CIDRAM['BlockInfo']['SignatureCount'] - $Infractions) > 0 &&
            strpos($CIDRAM['BlockInfo']['rURI'], 'administrator/') !== false &&
            strpos($CIDRAM['BlockInfo']['WhyReason'], 'POST RFI') !== false,
            'Joomla plugins update bypass (POST RFI conflict)'
        ); // 2017.05.10

        $Trigger(preg_match('~(?:=\[\\\\|%5C\]|\(\)|=%5Bphp%5D|=\[php\]|\\\\\]|=\[%5C|`)~i', $RawInput), 'POST BBCESC/BBCEX/EX'); // 2017.03.01

        $Trigger(preg_match(
            '~(?:%61%(6c%6c%6f%77%5f%75%72%6c%5f%69%6e%63%6c%75%64%65%3d%6f%6e|7' .
            '5%74%6f%5f%70%72%65%70%65%6e%64%5f%66%69%6c%65%3d%70%68%70%3a%2f%2f' .
            '%69%6e%70%75%74)|%63%67%69%2e%(66%6f%72%63%65%5f%72%65%64%69%72%65%' .
            '63%74%3d%30|72%65%64%69%72%65%63%74%5f%73%74%61%74%75%73%5f%65%6e%7' .
            '6%3d%30)|%64%69%73%61%62%6c%65%5f%66%75%6e%63%74%69%6f%6e%73%3d%22%' .
            '22|%6f%70%65%6e%5f%62%61%73%65%64%69%72%3d%6e%6f%6e%65|%73%(61%66%6' .
            '5%5f%6d%6f%64%65%3d%6f%66%66|75%68%6f%73%69%6e%2e%73%69%6d%75%6c%61' .
            '%74%69%6f%6e%3d%6f%6e))~',
            $RawInputSafe
        ), 'Plesk hack'); // 2017.03.01

        $Trigger(preg_match('~(?:6\D*1\D*6\D*6\D*9\D*4\D*7\D*8\D*5)~i', $RawInput), 'Spam attempt'); // 2017.03.01
        $Trigger(preg_match('~//dail' . 'ydigita' . 'ldeals' . '\.info/~i', $RawInput), 'Spam attempt'); // 2017.03.01

        $Trigger(preg_match(
            '~C[46][iy]1F[12]EA7217PB(?:DF|TL)[15]FlcH(?:77|98)s[0O]pf[0O](?:%2f' .
            '|.)[Sr]1[Zt](?:15|76)(?:%2f|.)(?:13ga|OKFae)~',
            $RawInput
        ), 'Compromised API key used in brute-force attacks'); // 2020.08.08

        $Trigger(preg_match('~streaming\.live365\.com/~i', $RawInput), 'Spamvertised domain'); // 2020.03.02

        /** These signatures can set extended tracking options. */
        if (
            $Trigger(preg_match('~/â\\x80¦x\.php~i', $RawInput), 'Probe attempt') || // 2017.03.01
            $Trigger(preg_match('~\([\'"](?:zwnobyai|awyoznvu)~', $RawInputSafe), 'Injection attempt') || // 2017.03.01
            $Trigger(preg_match('~^/\?-~', $RawInput), 'Hack attempt') || // 2017.03.01
            $Trigger(strpos($RawInputSafe, '$_' . '[$' . '__') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(strpos($RawInputSafe, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(preg_match('~&author_name=(?:%5b|\[)~', $RawInputSafe), 'Bot detection') // 2017.03.01
        ) {
            $CIDRAM['Tracking options override'] = 'extended';
        }
    }

    /** Reporting. */
    if (!empty($CIDRAM['BlockInfo']['IPAddr'])) {
        if (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Accessing quarantined files not allowed') !== false) {
            $CIDRAM['Reporter']->report([15], ['Unauthorised attempt to access quarantined files detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Compromised API key') !== false) {
            $CIDRAM['Reporter']->report([15], ['Unauthorised use of known compromised API key detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'FancyBox exploit attempt') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['FancyBox hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Hack attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Nesting attack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Nesting attack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Non-escaped characters in POST') !== false) {
            $CIDRAM['Reporter']->report([19], ['Non-escaped characters in POST detected (bot indicator).'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Null truncation attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Null truncation attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Overflow attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Overflow attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'POST BBCESC/BBCEX/EX') !== false) {
            $CIDRAM['Reporter']->report([15], ['POST BBCESC/BBCEX/EX detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Path hack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Path hack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Pipe hack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Pipe hack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Plesk hack') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['Plesk hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Probe attempt') !== false) {
            $CIDRAM['Reporter']->report([19], ['Probe detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query SQLi') !== false) {
            $CIDRAM['Reporter']->report([16], ['SQL injection attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query command injection') !== false) {
            $CIDRAM['Reporter']->report([15], ['Query command injection attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query global variable hack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Query global variable hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query script injection') !== false) {
            $CIDRAM['Reporter']->report([15], ['Query script injection attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Shell upload attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Shell upload attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Spam attempt') !== false) {
            $CIDRAM['Reporter']->report([10], ['Detected a spambot attempting to drop its payload.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Spam attempt') !== false) {
            $CIDRAM['Reporter']->report([10, 19], ['Detected a spambot attempting to drop its payload.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'WP hack attempt') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['WordPress hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Traversal attack') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['Traversal attack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'WSO not allowed') !== false) {
            $CIDRAM['Reporter']->report([20, 21], ['Unauthorised attempt to connect to WSO webshell detected (host might be compromised).'], $CIDRAM['BlockInfo']['IPAddr']);
        }
    }

    /**
     * Signatures based on the original REQUEST_URI start from here.
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if ($CIDRAM['Config']['extras']['uri'] && !empty($_SERVER['REQUEST_URI'])) {
        /** Guard. */
        if (empty($CIDRAM['BlockInfo']['IPAddr'])) {
            return;
        }

        $LCReqURI = str_replace("\\", '/', strtolower($_SERVER['REQUEST_URI']));

        /** Probing for webshells/backdoors. */
        if ($Trigger(preg_match(
            '~^/*(?:' .
            'old/wp-admin/install\.php|' .
            'test/wp-includes/wlwmanifest\.xml|' .
            'vendor/phpunit/phpunit/src/Util/PHP/(?:eval-stdin|kill)\.php' .
            ')~i',
            $LCReqURI
        ) || preg_match(
            '~(?:' .
            'c(?:9|10)\d+|gh[0o]st|gzismexv|h6ss|icesword|itsec|p[Hh]p(?:1|_niu_\d+|版iisspy|大马|一句话(?:木马|扫描脚本程序)?)|' .
            'poison|session91|shell|silic|tk(?:_dencode_\d+)?|' .
            'webshell-[a-z\d]+|wloymzuk|wso\d\.\d\.\d|xiaom|xw|zone_hackbar(?:_beutify_other)?' .
            ')\.php$~i',
            $LCReqURI
        ), 'Probing for webshells/backdoors')) {
            $CIDRAM['Reporter']->report([15, 21], ['Caught probing for webshells/backdoors.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2019.08.12 mod 2020.11.29

        /** Probing for exposed Git data. */
        if ($Trigger(preg_match('~^/*\.git~i', $LCReqURI), 'Probing for exposed git data')) {
            $CIDRAM['Reporter']->report([15, 21], ['Caught probing for exposed git data.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2019.08.12

        /** Probing for exposed SSH data. */
        if ($Trigger(preg_match('~^/*\.ssh~i', $LCReqURI), 'Probing for exposed SSH data')) {
            $CIDRAM['Reporter']->report([15, 22], ['Caught probing for exposed SSH data.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2019.08.12

        /** Probing for vulnerable routers. */
        if ($Trigger(preg_match('~^/*HNAP1~i', $LCReqURI), 'Probing for vulnerable routers')) {
            $CIDRAM['Reporter']->report([15, 23], ['Caught probing for vulnerable routers.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2019.08.12
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]($Infractions);
