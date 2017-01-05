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
 * This file: Optional security extras module (last modified: 2017.01.05).
 *
 * Many thanks to Michael Hopkins, the creator of ZB Block (GNU/GPLv2), and to
 * the community behind it (Spambot Security) for inspiring/developing many of
 * the signatures contained within this module.
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

/** Directory traversal protection (2016.12.31). */
$Trigger(
    preg_match("\x01" . '(?:(/|%5[cf])\.+(/|%5[cf])|(/|%5[cf]){3,})' . "\x01i", str_replace("\\", '/', $CIDRAM['BlockInfo']['rURI'])),
    'Traversal attack'
);

/** Query-based signatures start from here. */
if (!empty($_SERVER['QUERY_STRING'])) {
    $Query = str_replace("\\", '/', strtolower(urldecode($_SERVER['QUERY_STRING'])));
    $QueryNoSpace = preg_replace('/\s/', '', $Query);

    $Trigger(preg_match('/\((?:["\']{2})?\)/', $QueryNoSpace), 'Command injection'); // 2016.12.31
    $Trigger(preg_match(
        '/(?:_once|able|as(c|hes|sert)|c(hr|ode|ontents)|e(cho|regi|scape|va' .
        'l)|ex(ec|ists)?|f(ile|late|unction)|get(c|csv|ss?)?|i(f|nclude)|len' .
        '(gth)?|nt|open|p(ress|lace|lode|uts)|print(f|_r)?|re(ad|place|quire' .
        '|store)|rot13|s(tart|ystem)|w(hile|rite))["\':(\[{<$]/',
    $QueryNoSpace), 'Command injection'); // 2016.12.31
    $Trigger(
        preg_match('/\$(?:globals|_cookie|_env|_files|_get|_post|_request|_server|_session)/', $QueryNoSpace),
        'Command injection'
    ); // 2016.12.31
    $Trigger(preg_match('/http_(?:cmd|sum)/', $QueryNoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/pa(?:rse_ini_file|ssthru)/', $QueryNoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/rewrite(?:cond|rule)/', $QueryNoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/u(?:nserialize|ploadedfile)/', $QueryNoSpace), 'Command injection'); // 2017.01.02
    $Trigger(strpos($QueryNoSpace, 'dotnet_load') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'execcgi') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'move_uploaded_file') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'symlink') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'tmp_name') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, '_contents') !== false, 'Command injection'); // 2016.12.31

    $Trigger(preg_match('/%(?:0[0-8bcef]|1)/i', $_SERVER['QUERY_STRING']), 'Non-printable characters in query'); // 2016.12.31

    $Trigger(preg_match('/(?:amp(;|%3b)){2,}/', $QueryNoSpace), 'Nesting attack'); // 2016.12.31
    $Trigger((
        strpos($CIDRAM['BlockInfo']['rURI'], '/ucp.php?mode=login') === false &&
        preg_match('/%(?:(25){2,}|(25)+27)/', $_SERVER['QUERY_STRING'])
    ), 'Nesting attack'); // 2017.01.01

    $Trigger(
        preg_match('/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/', $QueryNoSpace),
        'Script injection'
    ); // 2017.01.05

    $Trigger(preg_match('/_(?:cookie|env|files|(ge|pos|reques)t|s(erver|ession))\[/', $QueryNoSpace), 'Global variable hack'); // 2017.01.01
    $Trigger(strpos($QueryNoSpace, 'globals['), 'Global variable hack'); // 2017.01.01

    $Trigger(substr($_SERVER['QUERY_STRING'], -3) === '%00', 'Null truncation attempt'); // 2016.12.31
    $Trigger(substr($_SERVER['QUERY_STRING'], -4) === '%000', 'Null truncation attempt'); // 2016.12.31
    $Trigger(substr($_SERVER['QUERY_STRING'], -5) === '%0000', 'Null truncation attempt'); // 2016.12.31

    $Trigger(strpos($QueryNoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt'); // 2017.01.02

    $Trigger(preg_match('/%(?:20\'|25[01u]|[46]1%[46]e%[46]4)/', $_SERVER['QUERY_STRING']), 'Hack attempt'); // 2017.01.05
    $Trigger(preg_match('/\'%2[05]/', $_SERVER['QUERY_STRING']), 'Hack attempt'); // 2017.01.05
    $Trigger(preg_match('/\|(?:include|require)/', $QueryNoSpace), 'Hack attempt'); // 2017.01.01
    $Trigger(strpos($Query, 'rm ' . '-rf') !== false, 'Hack attempt', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($QueryNoSpace, "'='") !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, '.php/login.php') !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, '1http:') !== false, 'Hack attempt'); // 2017.01.01
    $Trigger(strpos($QueryNoSpace, ';c' . 'hmod7' . '77') !== false, 'Hack attempt', '', $InstaBan); // 2017.01.05
    $Trigger(strpos($_SERVER['QUERY_STRING'], '=-1%27') !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(substr($QueryNoSpace, 0, 1) === ';', 'Hack attempt'); // 2017.01.05
    $Trigger(substr($QueryNoSpace, 0, 6) === 'pull[]', 'Hack attempt'); // 2017.01.05

    $Trigger(substr($QueryNoSpace, 0, 2) === '()', 'Bash/Shellshock', '', $InstaBan); // 2017.01.05

    $Trigger(strpos($QueryNoSpace, 'allow_url_include=on') !== false, 'Plesk hack'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'auto_prepend_file=php://input') !== false, 'Plesk hack'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'cgi.force_redirect=0') !== false, 'Plesk hack'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'cgi.redirect_status_env=0') !== false, 'Plesk hack'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'disable_functions=""') !== false, 'Plesk hack'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'open_basedir=none') !== false, 'Plesk hack'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'safe_mode=off') !== false, 'Plesk hack'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'suhosin.simulation=on') !== false, 'Plesk hack'); // 2017.01.05

    $Trigger(substr($QueryNoSpace, 0, 1) === '-', 'Probe attempt'); // 2017.01.05

    $Trigger(strpos($_SERVER['QUERY_STRING'], '++++') !== false, 'Overflow attempt'); // 2017.01.05

    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $QueryNoSpace), 'XSS attack'); // 2017.01.03

    $Trigger(count($_REQUEST) >= 500, 'Hack attempt', 'Too many request variables sent!'); // 2017.01.01

}

/** UA-based signatures start from here (UA = User Agent). */
if ($CIDRAM['BlockInfo']['UA'] && !$Trigger(strlen($CIDRAM['BlockInfo']['UA']) > 4096, 'Bad UA', 'User agent string is too long!')) {
    $UA = str_replace("\\", '/', strtolower(urldecode($CIDRAM['BlockInfo']['UA'])));
    $UANoSpace = preg_replace('/\s/', '', $UA);

    $Trigger(preg_match('/\((?:["\']{2})?\)/', $UANoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match(
        '/(?:_once|able|as(c|hes|sert)|c(hr|ode|ontents)|e(cho|regi|scape|va' .
        'l)|ex(ec|ists)?|f(ile|late|unction)|get(c|csv|ss?)?|i(f|nclude)|len' .
        '(gth)?|open|p(ress|lace|lode|uts)|print(f|_r)?|re(ad|place|quire|st' .
        'ore)|rot13|s(tart|ystem)|w(hile|rite))["\':(\[{<$]/',
    $UANoSpace), 'Command injection'); // 2017.01.02
    $Trigger(
        preg_match('/\$(?:globals|_cookie|_env|_files|_get|_post|_request|_server|_session)/', $UANoSpace),
        'Command injection'
    ); // 2017.01.02
    $Trigger(preg_match('/http_(?:cmd|sum)/', $UANoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/pa(?:rse_ini_file|ssthru)/', $UANoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/rewrite(?:cond|rule)/', $UANoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/u(?:nserialize|ploadedfile)/', $UANoSpace), 'Command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'dotnet_load') !== false, 'Command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'execcgi') !== false, 'Command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'move_uploaded_file') !== false, 'Command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'symlink') !== false, 'Command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'tmp_name') !== false, 'Command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, '_contents') !== false, 'Command injection'); // 2017.01.02

    $Trigger(preg_match('/%(?:0[0-8bcef]|1)/i', $CIDRAM['BlockInfo']['UA']), 'Non-printable characters in UA'); // 2017.01.02

    $Trigger(
        preg_match('/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/', $UANoSpace),
        'Script injection'
    ); // 2017.01.05

    $Trigger(preg_match('/_(?:cookie|env|files|(ge|pos|reques)t|s(erver|ession))\[/', $UANoSpace), 'Global variable hack'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'globals[') !== false, 'Global variable hack'); // 2017.01.02

    $Trigger(strpos($UANoSpace, '$_' . '[$' . '__') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02

    $Trigger(strpos($UA, 'rm ' . '-rf') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'fu' . 'ck') !== false, 'Hack UA', '', $InstaBan); // 2017.01.04
    $Trigger(strpos($UANoSpace, 'r0' . '0t') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'sh' . 'el' . 'l_' . 'ex' . 'ec') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, '}__') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02

    $Trigger(preg_match('/(?:x(rumer|pymep)|хрумер)/', $UANoSpace), 'Spam UA', '', $InstaBan); // 2017.01.02
    $Trigger(preg_match('/[<\[](?:a|link|url)[ =>\]]/', $UA), 'Spam UA'); // 2017.01.02
    $Trigger(strpos($UANoSpace, '/how-') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, '>click') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, 'start.exe') !== false, 'Spam UA'); // 2017.01.02
    $Trigger(preg_match(
        '/(?:avelox|b(dsm|ea?stiality|iloba)|c(ialis|igar|heap)|d(eltasone|r' .
        'ugs)|eroti[ck]|forex|g(abapentin|eriforte|inkg?o|uestbook)|hentai|i' .
        'n(cest|come|vestment)|k(amagra|eylog)|l(axative|esbian|evitra|exap|' .
        'iker\.profile|ipitor|olita|uxury)|m(elaleuca|enthol)|n(eurontin|olv' .
        'adex)|o(rgasm|utlet)|p(axil|harma|illz|lavix|orn|r(0n|opecia|osti))' .
        '|r(eviewsx|ogaine)|s(ex[xy]|hemale|limy|terapred|ynthroid)|t(entacl' .
        'e|op(less|sites))|vi(agra|olation|tol)|xanax)/',
    $UANoSpace), 'Spam UA'); // 2017.01.05

    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $UANoSpace), 'XSS attack'); // 2017.01.03

    $Trigger(strpos($UA, '   ') !== false, 'Bad UA'); // 2017.01.02

}
