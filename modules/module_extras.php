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
 * This file: Optional security extras module (last modified: 2017.10.27).
 *
 * Many thanks to Michael Hopkins, the creator of ZB Block (GNU/GPLv2), and to
 * the community behind it (Spambot Security) for inspiring/developing many of
 * the signatures contained within this module.
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Inherit bypass closure (see functions.php). */
$Bypass = $CIDRAM['Bypass'];

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
$InstaBan = ['Options' => ['TrackTime' => 31536000, 'TrackCount' => 1000]];

$Trigger(count($_REQUEST) >= 500, 'Hack attempt', 'Too many request variables sent!'); // 2017.01.01

/** Needed for some bypasses specific to WordPress (detects whether we're running as a WordPress plugin). */
$is_WP_plugin = (defined('ABSPATH') || strtolower(str_replace("\\", '/', substr(__DIR__, -31))) === 'wp-content/plugins/cidram/vault');

/**
 * Signatures based on the reconstructed URI start from here.
 * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
 */
if ($CIDRAM['BlockInfo']['rURI']) {
    $LCNrURI = str_replace("\\", '/', strtolower($CIDRAM['BlockInfo']['rURI']));

    /** Directory traversal protection. */
    $Trigger(preg_match('~(?:/|%5[cf])\.{2,}(?:/|%5[cf])~i', $LCNrURI), 'Traversal attack'); // 2017.01.13

    /** Detect bad/dangerous/malformed requests. */
    $Trigger(preg_match('~(?:(/|%5[cf])\.(/|%5[cf])|(/|%5[cf]){3,}|[\x00-\x1f\x7f])~i', $LCNrURI), 'Bad request'); // 2017.01.13

    $Trigger(preg_match('~(?:(/%e2%80%a6x|shrift)\.php|/get?(fwversion|mac))~', $LCNrURI), 'Hack attempt', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match('~author=\d+~i', $LCNrURI), 'WordPress user enumeration not allowed'); // 2017.03.22

    /** Joomla image inserting tool bypass (WordPress user enumeration conflict). */
    $Bypass(
        ($CIDRAM['BlockInfo']['SignatureCount'] - $Infractions) > 0 &&
        strpos($LCNrURI, 'administrator/') !== false &&
        strpos($CIDRAM['BlockInfo']['WhyReason'], 'WordPress user enumeration not allowed') !== false,
    'Joomla image inserting tool bypass (WordPress user enumeration conflict)'); // 2017.06.01

    $Trigger((
        strpos($LCNrURI, 'wp-print.php?script=1') !== false || // 2017.10.07
        strpos($LCNrURI, 'css/newgolden.php') !== false // 2017.10.07
    ), 'WP hack attempt');

    /** WSO is a common PHP backdoor/trojan. */
    $Trigger(preg_match('~[\x5c/]wso\.php~i', $LCNrURI), 'WSO not allowed'); // 2017.03.22

    $Trigger(preg_match('~\.(?:bak|cgi|php)\.suspected~i', $LCNrURI), 'Accessing quarantined files not allowed'); // 2017.03.22

}

/**
 * Query-based signatures start from here.
 * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
 */
if (!empty($_SERVER['QUERY_STRING'])) {
    $Query = str_replace("\\", '/', strtolower(urldecode($_SERVER['QUERY_STRING'])));
    $QueryNoSpace = preg_replace('/\s/', '', $Query);

    $Trigger(preg_match('/\((?:["\']{2})?\)/', $QueryNoSpace), 'Command injection'); // 2016.12.31

    $Trigger(preg_match(
        '/(?:_once|able|as(c|hes|sert)|c(hr|ode|ontents)|e(cho|regi|scape|va' .
        'l)|ex(ec|ists)?|f(ile|late|unction)|get(c|csv|ss?)?|i(f|nclude)|len' .
        '(gth)?|nt|open|p(ress|lace|lode|uts)|print(f|_r)?|re(ad|place|quire' .
        '|store)|rot13|s(tart|ystem)|w(hil|rit)e)["\':(\[{<$]/',
    $QueryNoSpace), 'Command injection'); // 2017.01.13

    $Trigger(preg_match(
        '/\$(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))/',
    $QueryNoSpace), 'Command injection'); // 2017.01.13

    $Trigger(preg_match('/http_(?:cmd|sum)/', $QueryNoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/pa(?:rse_ini_file|ssthru)/', $QueryNoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/rewrite(?:cond|rule)/', $QueryNoSpace), 'Command injection'); // 2017.01.02
    $Trigger(preg_match('/u(?:nserializ|ploadedfil)e/', $QueryNoSpace), 'Command injection'); // 2017.01.13
    $Trigger(strpos($QueryNoSpace, 'dotnet_load') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'execcgi') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'move_uploaded_file') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'symlink') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, 'tmp_name') !== false, 'Command injection'); // 2016.12.31
    $Trigger(strpos($QueryNoSpace, '_contents') !== false, 'Command injection'); // 2016.12.31

    $Trigger(preg_match('/%(?:0[0-8bcef]|1)/i', $_SERVER['QUERY_STRING']), 'Non-printable characters in query'); // 2016.12.31

    $Trigger(preg_match('/(?:amp(;|%3b)){2,}/', $QueryNoSpace), 'Nesting attack'); // 2016.12.31
    $Trigger(preg_match('/\?(?:&|cmd=)/', $QueryNoSpace), 'Nesting attack'); // 2017.02.25

    $Trigger((
        strpos($CIDRAM['BlockInfo']['rURI'], '/ucp.php?mode=login') === false &&
        preg_match('/%(?:(25){2,}|(25)+27)/', $_SERVER['QUERY_STRING'])
    ), 'Nesting attack'); // 2017.01.01

    $Trigger(preg_match(
        '/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/',
    $QueryNoSpace), 'Script injection'); // 2017.01.05

    $Trigger(preg_match(
        '/_(?:cookie|env|files|get|post|request|se(rver|ssion))\[/',
    $QueryNoSpace), 'Global variable hack'); // 2017.01.13

    $Trigger(strpos($QueryNoSpace, 'globals['), 'Global variable hack'); // 2017.01.01

    $Trigger(substr($_SERVER['QUERY_STRING'], -3) === '%00', 'Null truncation attempt'); // 2016.12.31
    $Trigger(substr($_SERVER['QUERY_STRING'], -4) === '%000', 'Null truncation attempt'); // 2016.12.31
    $Trigger(substr($_SERVER['QUERY_STRING'], -5) === '%0000', 'Null truncation attempt'); // 2016.12.31

    $Trigger(strpos($QueryNoSpace, '$_' . '[$' . '__') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.03.01
    $Trigger(strpos($QueryNoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.03.01

    $Trigger(preg_match('/%(?:20\'|25[01u]|[46]1%[46]e%[46]4)/', $_SERVER['QUERY_STRING']), 'Hack attempt'); // 2017.01.05
    $Trigger(preg_match('/&arrs[12]\[\]=/', $QueryNoSpace), 'Hack attempt'); // 2017.02.25
    $Trigger(preg_match('/p(?:ath|ull)\[?\]/', $QueryNoSpace), 'Hack attempt'); // 2017.01.06
    $Trigger(preg_match('/user_login,\w{4},user_(?:pass|email|activation_key)/', $QueryNoSpace), 'WP hack attempt'); // 2017.02.18
    $Trigger(preg_match('/\'%2[05]/', $_SERVER['QUERY_STRING']), 'Hack attempt'); // 2017.01.05
    $Trigger(preg_match('/\|(?:include|require)/', $QueryNoSpace), 'Hack attempt'); // 2017.01.01
    $Trigger(strpos($Query, 'rm ' . '-rf') !== false, 'Hack attempt', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($QueryNoSpace, "'='") !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, '.php/login.php') !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, '1http:') !== false, 'Hack attempt'); // 2017.01.01
    $Trigger(strpos($QueryNoSpace, ';c' . 'hmod7' . '77') !== false, 'Hack attempt', '', $InstaBan); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, 'id=\'') !== false, 'Hack attempt'); // 2017.02.18
    $Trigger(strpos($QueryNoSpace, 'name=lobex21.php') !== false, 'Hack attempt'); // 2017.02.18
    $Trigger(strpos($QueryNoSpace, 'php://') !== false, 'Hack attempt'); // 2017.02.18
    $Trigger(strpos($QueryNoSpace, 'tmunblock.cgi') !== false, 'Hack attempt'); // 2017.02.18
    $Trigger(strpos($_SERVER['QUERY_STRING'], '=-1%27') !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(substr($QueryNoSpace, 0, 1) === ';', 'Hack attempt'); // 2017.01.05

    $Trigger(substr($QueryNoSpace, 0, 2) === '()', 'Bash/Shellshock', '', $InstaBan); // 2017.01.05

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
    $Trigger(strpos($QueryNoSpace, '0x31303235343830303536') !== false, 'Probe attempt', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match(
        '/\[(?:[alrw]\]|classes|file|itemid|l(astrss_ap_enabled|oadfile|ocal' .
        'serverfile)|pth|src)/',
    $QueryNoSpace), 'Probe attempt'); // 2017.01.17

    $Trigger(strpos($QueryNoSpace, '+result:') !== false, 'Spam attempt'); // 2017.01.08
    $Trigger(strpos($QueryNoSpace, 'result:+\\') !== false, 'Spam attempt'); // 2017.01.08

    $Trigger(preg_match('/(?:["\'];|[;=]\|)/', $QueryNoSpace), 'Execution attempt'); // 2017.01.13
    $Trigger(preg_match('/[\'"`]sysadmin[\'"`]/', $QueryNoSpace), 'Generic attack attempt'); // 2017.02.25
    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $QueryNoSpace), 'XSS attack'); // 2017.01.03
    $Trigger(preg_match('/[\'"`]|[\'"`]/', $QueryNoSpace), 'Pipe detected'); // 2017.01.08
    $Trigger(strpos($QueryNoSpace, 'num_replies=77777') !== false, 'Overflow attempt'); // 2017.02.25
    $Trigger(strpos($_SERVER['QUERY_STRING'], '++++') !== false, 'Overflow attempt'); // 2017.01.05
    $Trigger(strpos($_SERVER['QUERY_STRING'], '->') !== false, 'Generic attack attempt'); // 2017.02.25

    $Trigger(strpos($QueryNoSpace, 'src=http:') !== false, 'RFI'); // 2017.02.18
    $Trigger(strpos($QueryNoSpace, 'path]=') !== false, 'Path hack'); // 2017.02.18

    $Trigger(strpos($QueryNoSpace, 'e9xmkgg5h6') !== false, 'Query error'); // 2017.02.18
    $Trigger(strpos($QueryNoSpace, '5889d40edd5da7597dfc6d1357d98696') !== false, 'Query error'); // 2017.02.18

    $Trigger(preg_match('/(?:keywords|query|searchword|terms)=%d8%b3%d9%83%d8%b3/', $QueryNoSpace), 'Unauthorised'); // 2017.02.18

    $Trigger(strpos($_SERVER['QUERY_STRING'], '??') !== false, 'Bad query'); // 2017.02.25
    $Trigger(strpos($_SERVER['QUERY_STRING'], ',0x') !== false, 'Bad query'); // 2017.02.25
    $Trigger(strpos($_SERVER['QUERY_STRING'], ',\'\',') !== false, 'Bad query'); // 2017.02.25

    $Trigger(preg_match('/id=.*(?:benchmark\(|id[xy]=|sleep\()/', $QueryNoSpace), 'SQLi'); // 2017.03.01
    $Trigger(preg_match(
        '/(?:(from|union|where).*select|then.*else|(o[nr]|where).*is null|(i' .
        'nner|left|outer|right) join)/',
    $QueryNoSpace), 'SQLi'); // 2017.03.01

    $Trigger(preg_match('/(?:(modez|osc|tasya)=|=((bot|scanner|shell)z|psybnc))/', $QueryNoSpace), 'Common shell/bot command', '', $InstaBan); // 2017.02.25

}

/**
 * UA-based signatures start from here (UA = User Agent).
 * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
 */
if ($CIDRAM['BlockInfo']['UA'] && !$Trigger(strlen($CIDRAM['BlockInfo']['UA']) > 4096, 'Bad UA', 'User agent string is too long!')) {
    $UA = str_replace("\\", '/', strtolower(urldecode($CIDRAM['BlockInfo']['UA'])));
    $UANoSpace = preg_replace('/\s/', '', $UA);

    $Trigger(preg_match('/\((?:["\']{2})?\)/', $UANoSpace), 'Command injection'); // 2017.01.02

    $Trigger(preg_match(
        '/(?:_once|able|as(c|hes|sert)|c(hr|ode|ontents)|e(cho|regi|scape|va' .
        'l)|ex(ec|ists)?|f(ile|late|unction)|get(c|csv|ss?)?|i(f|nclude)|len' .
        '(gth)?|open|p(ress|lace|lode|uts)|print(f|_r)?|re(ad|place|quire|st' .
        'ore)|rot13|s(tart|ystem)|w(hil|rit)e)["\':(\[{<$]/',
    $UANoSpace), 'Command injection'); // 2017.01.20

    $Trigger(preg_match(
        '/\$(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))/',
    $UANoSpace), 'Command injection'); // 2017.01.13

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

    $Trigger(preg_match(
        '/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/',
    $UANoSpace), 'Script injection'); // 2017.01.08

    $Trigger(preg_match(
        '/(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))\[/',
    $UANoSpace), 'Global variable hack'); // 2017.01.13

    $Trigger(strpos($UANoSpace, '$_' . '[$' . '__') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02

    $Trigger(preg_match('/0wn[3e]d/', $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(preg_match('/:(\{[a-z]:|[a-z0-9][;:]\})/', $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.01.20
    $Trigger(preg_match('/h[4a]c' . 'k(?:e[dr]|ing|t([3e][4a]m|[0o]{2}l))/', $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(preg_match('/Y[EI]$/', $CIDRAM['BlockInfo']['UA']), 'Possible/Suspected hack UA'); // 2017.01.06
    $Trigger(strpos($UA, 'rm ' . '-rf') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UA, 'wordpress ha') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'if(') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'r0' . '0t') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'sh' . 'el' . 'l_' . 'ex' . 'ec') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'whcc/') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, '\0\0\0') !== false, 'Hack UA', '', $InstaBan); // 2017.01.09
    $Trigger(strpos($UANoSpace, '}__') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02

    $Trigger(preg_match(
        '/(?:cha0s|f(hscan|uck)|havij|jdatabasedrivermysqli|morfeus|urldumper|xmlset_roodkcable|zollard)/',
    $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.02.25

    $Trigger(strpos($UA, 'select ') !== false, 'UASQLi'); // 2017.02.25

    $Trigger(strpos($UANoSpace, 'captch') !== false, 'CAPTCHA cracker UA'); // 2017.01.08

    $Trigger(preg_match('~(?:(aihit|casper)bot|mamac(asper|yber)|mozilla/0)~', $UANoSpace), 'Probe UA', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match(
        '~(?:^b55|-agent-|auto_?http|bigbrother|cybeye|d((iavol|ragoste)a|ow' .
        'nloaddemon)|e(ak01ag9|catch)|i(chiro|ndylibrary|ntelium)|k(angen|mc' .
        'crew)|libwww-pavuk|m(o(get|zillaxyz)|sie6\.0.*deepnet)|n(et(ants|co' .
        'mber)|s8/0\.9\.6)|p(atchone|aros|entru|lanetwork|robe)|riddler|s(as' .
        'qia|ledink|noopy|tingbot)|toata|updown_tester|w(hitehataviator|orio' .
        ')|xirio|you?dao|zmeu)~',
    $UANoSpace), 'Probe UA'); // 2017.02.25

    $Trigger(preg_match('/(?: obot|ie 5\.5 compatible browser)/', $UA), 'Probe UA'); // 2017.02.02
    $Trigger(preg_match('~(?:p(hoton/|ogs/2\.0))~', $UANoSpace), 'Probe UA'); // 2017.02.25

    $Trigger(strpos($UANoSpace, 'wopbot') !== false, 'Bash/Shellshock UA', '', $InstaBan); // 2017.01.06

    $Trigger(preg_match('/(?:x(rumer|pymep)|хрумер)/', $UANoSpace), 'Spam UA', '', $InstaBan); // 2017.01.02
    $Trigger(preg_match('/[<\[](?:a|link|url)[ =>\]]/', $UA), 'Spam UA'); // 2017.01.02
    $Trigger(preg_match('/^\.?=/', $UANoSpace), 'Spam UA'); // 2017.01.07
    $Trigger(strpos($UANoSpace, '/how-') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, '>click') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, 'ruru)') !== false, 'Spam UA'); // 2017.01.07

    $Trigger(preg_match(
        '/(?:a(btasty|dwords|llsubmitter|velox)|b(acklink|ad-neighborhood|ds' .
        'm|ea?stiality|iloba|ork-edition|uyessay)|c(asino|ialis|igar|heap|ou' .
        'rsework)|d(eltasone|issertation|rugs)|e(ditionyx|roti[ck]|stimatewe' .
        'bstats)|f(orex|unbot)|g(abapentin|erifort|inkg?o|uestbook)|h(entai|' .
        'rbot)|in(cest|come|vestment)|jailbreak|k(amagra|eylog)|l(axative|e(' .
        'sbian|vitra|xap)|i(ker\.profile|nk(ba|che)ck|pitor)|olita|uxury|yco' .
        'sa\.se)|m(ail\.ru|e(laleuca|nthol)|ixrank|rie8pack)|n(e(rdybot|tzch' .
        'eckbot|urontin)|olvadex)|o(rgasm|utlet)|p(axil|harma|illz|lavix|orn' .
        '|r(0n|opecia|osti))|r(eviewsx|ogaine)|s(ex[xy]|hemale|ickseo|limy|p' .
        'utnik|tart\.exe|terapred|ynthroid)|t(entacle|[0o]p(hack|less|sites)' .
        ')|u(01-2|nlock)|v((aluation|oila)bot|arifort|[1i](agra|olation|tol)' .
        ')|warifort|xanax|zdorov)/',
    $UANoSpace), 'Spam UA'); // 2017.05.02

    $Trigger(preg_match(
        '/(?: (audit|href|mra |quibids )|\(build 5339\))/',
    $UA), 'Spam UA'); // 2017.02.02

    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $UANoSpace), 'XSS attack'); // 2017.01.03
    $Trigger(strpos($UANoSpace, '`') !== false, 'Execution attempt'); // 2017.01.13

    $Trigger(preg_match(
        '/(?:digger|e((mail)?collector|mail(ex|search|spider|siphon)|xtract(' .
        'ion|or))|iscsystems|microsofturl|oozbot|psycheclone)/',
    $UANoSpace), 'Email havester'); // 2017.01.07

    $Trigger(strpos($UANoSpace, 'email') !== false, 'Possible/Suspected email havester'); // 2017.01.06

    $Trigger(preg_match('/%(?:[01][0-9a-f]|2[257]|3[ce]|[57][bd]|[7f]f)/', $UANoSpace), 'Bad UA'); // 2017.01.06

    $Trigger(preg_match(
        '/(?:loadimpact|re-?animator|root|webster)/',
    $UANoSpace), 'Banned UA', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match('/test\'?$/', $UANoSpace), 'Banned UA'); // 2017.02.02
    $Trigger(preg_match('/^(?:\'?test|-|default|foo)/', $UANoSpace), 'Banned UA'); // 2017.02.02
    $Trigger(preg_match('/^[\'"].*[\'"]$/', $UANoSpace), 'Banned UA'); // 2017.02.02
    $Trigger(strpos($UA, '   ') !== false, 'Banned UA'); // 2017.02.02
    $Trigger(strpos($UANoSpace, '(somename)') !== false, 'Banned UA', '', $InstaBan); // 2017.02.02

    $Trigger(preg_match(
        '/(?:_sitemapper|3mir|a(boundex|dmantx|dnormcrawler|dvbot|lphaserver' .
        '|thens|ttache)|bl(ekko|ogsnowbot)|c(mscrawler|o(ccoc|llect|modo-web' .
        'inspector-crawler|mpspy)|rawler4j)|d(atacha|igout4uagent|ioscout|ki' .
        'mrepbot|sarobot)|e(asou|xabot)|f(astenterprisecrawler|astlwspider|i' .
        'nd?bot|indlinks|loodgate|r[_-]?crawler)|grapeshot|h(rcrawler|ubspot' .
        ')|i(mrbot|ntegromedb|p-?web-?crawler|rcsearch|rgrabber)|jadynavebot' .
        '|komodiabot|lin(guee|kpad)|m((ajestic|j)12|agnet|eanpath|entormate|' .
        'fibot|ignify)|nutch|omgilibot|p(ackrat|cbrowser|lukkie|surf)|r(eape' .
        'r|sync)|s(aidwot|alad|cspider|ees\.co|hai|iteexplorer|[iy]pho' .
        'n|truct\.it|upport\.wordpress\.com)|t(akeout|asapspider|weetmeme)|u' .
        'ser-agent|v(isaduhoc|onchimpenfurlr)|w(ebtarantula|olf)|y(acy|isous' .
        'pider|[ry]spider|un(rang|yun)))/',
    $UANoSpace), 'Banned UA'); // 2017.02.25

    $Trigger(preg_match('/(?:80legs|chinaclaw)/', $UANoSpace), 'Scraper UA', '', $InstaBan); // 2017.01.08
    $Trigger(preg_match('/^(?:abot|spider)/', $UANoSpace), 'Scraper UA'); // 2017.01.07
    $Trigger(strpos($UANoSpace, 'fetch/') !== false, 'Scraper UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'vlc/') !== false, 'Possible/Suspected scraper UA'); // 2017.01.07

    $Trigger(preg_match(
        '/(?:3(60spider|d-ftp)|a(6-indexer|ccelo|ffinity|ghaven|href|ipbot|n' .
        'alyticsseo|pp3lewebkit|r(chivebot|tviper))|b(azqux|ender|i(nlar|tvo' .
        '|xo)|nf.fr|ogahn|oitho|pimagewalker)|c(cbot|entiverse|msworldmap|om' .
        'moncrawl|overscout|r4nk|rawlfire|uriousgeorge|ydral)|d(atenbank|ayl' .
        'ife|ebate|igext|(cp|isco|ouban|ownload)bot|owjones|tsagent)|e((na|u' .
        'ro|xperi)bot|nvolk|vaal|zoom)|f(dm|etch(er.0|or)|ibgen)|g(alaxydown' .
        'loads|et(download\.ws|ty|url11)|slfbot|urujibot)|h(arvest|eritrix|o' .
        'lmes|ttp(fetcher|unit)|ttrack)|i(mage(.fetcher|walker)|linkscrawler' .
        '|n(agist|docom|fluencebot)|track)|j(akarta|ike)|k(ey(wenbot|wordsea' .
        'rchtool)|imengi|kman)|l(arbin|ink(dex|walker)|iperhey|(t|ush)bot)|m' .
        '(a(hiti|honie|ttters)|iabot|lbot|ormor|ot-v980|rchrome|ulticrawler)' .
        '|n(e(ofonie|testate|wsbot)|ineconnections)|o(afcrawl|fflinenavigato' .
        'r|odlebot)|p(age(fetch|gett|_verifi)er|anscient|ath2|ic(grabber|s|t' .
        'snapshot|turefinder)|i(pl|xmatch|xray)|oe-component-client-|owermar' .
        'ks|roximic|(s|ure)bot|urity)|qqdownload|r(ankivabot|ebi-shoveler|ev' .
        'erseget|ganalytics|ocketcrawler|sscrawl|ulinki)|s(afeassign|bider|b' .
        'l[.-]bot|crap[ey]|emrush|eo(eng|profiler|stat)|istrix|ite(bot|intel' .
        ')|n[iy]per|olomono|pbot|pyder|search|webot)|t(-h-u-n|agsdir|ineye|o' .
        'pseo|raumacadx|urnitinbot)|u(12bot|p(downer|ictobot))|v(bseo|isbot|' .
        'oyager)|w(arebay|auuu|bsearchbot|eb(alta|capture|download|ripper)|i' .
        'kio|indows(3|seven)|inhttp|khtmlto|orldbot|otbox)|xtractorpro|yoofi' .
        'nd)/',
    $UANoSpace), 'Scraper UA'); // 2017.07.21

    $Trigger(preg_match(
        '/(?:c(hilkat|copyright)|flipboard|g(ooglealerts|rub)|python)/',
    $UANoSpace), 'Possible/Suspected scraper UA'); // 2017.01.07

    $Trigger(preg_match('/(?:brandwatch|magpie)/', $UANoSpace), 'Snoop UA', '', $InstaBan); // 2017.01.13
    $Trigger(strpos($UANoSpace, 'catch') !== false, 'Risky UA'); // 2017.01.13

    $Trigger(preg_match('/(?:anonymous|vpngate)/', $UANoSpace), 'Proxy UA'); // 2017.01.13

    $Trigger(preg_match(
        '/(?:cncdialer|d(esktopsmiley|s_juicyaccess)|foxy.1|genieo|hotbar|ic' .
        'afe|m(utant|yway)|o(otkit|ssproxy)|qqpinyinsetup|si(cent|mbar)|tenc' .
        'enttraveler|wsr-agent|zeus)/',
    $UANoSpace), 'Malware UA'); // 2017.01.13

    $Trigger(preg_match('/(?:360se|theworld)\)/', $UANoSpace), 'Malware UA'); // 2017.01.13

    $Trigger(preg_match(
        '/(?:200please|analyzer|awcheck|blex|c(entric|omment|razywebcrawler)' .
        '|d(ataprovider|ot(bot|comdotnet|netdotcom))|m(egaindex|oreover|oz\.' .
        'com)|nextgensearchbot|pagesinventory|profiler|r(6_|adian6|ogerbot)|' .
        's(earchmetricsbot|eo(hunt|kicks|mon|tool)|phider)|vagabondo|vbseo\.' .
        'com|w(ebm(astercoffee|eup)|ise-guys))/',
    $UANoSpace), 'SEO UA'); // 2017.03.03

    $Trigger(preg_match(
        '~(?:a(bonti|ccserver|cme.spider|nyevent-http|ppengine)|b(igbozz|lac' .
        'kbird|logsearch|logbot|salsa)|c(atexplorador|liqzbot|ontextad|orpor' .
        'ama|rowsnest|yberpatrol)|d(bot/|le_spider|omainappender|umprendertr' .
        'ee)|flightdeckreportsbot|g(imme60|ooglebenjojo)|http-?(agent|client' .
        ')|i(ps-agent|sitwp)|k(2spider|emvi)|l(exxebot|ivelapbot|wp)|m(acinr' .
        'oyprivacyauditors|asscan|etaintelligence)|n(aver|ettrapport|icebot|' .
        'mapscriptingengine|rsbot)|p(4bot|4load|acrawler|ageglimpse|arsijoo|' .
        'egasusmonitoring|hantomjs|hpcrawl|ingdom|rlog)|r(arelyused|obo(cop|' .
        'spider)|yze)|s(creener|itedomain|mut|nap(preview)?bot|oapclient|oci' .
        'al(ayer|searcher)|ogou|ohuagent|oso|pyglass|quider|ynapse)|urlappen' .
        'dbot|w(asalive|atchmouse|eb(-monitoring|bot|masteraid|money|thumbna' .
        'il)|hatweb|ikiapiary|in(http|inet)|maid\.com|sr-agent|wwtype)|xenu|' .
        'xovi|yeti|zibber|zurichfinancialservices|^m$)~',
    $UANoSpace), 'Unauthorised'); // 2017.02.25

    $Trigger(preg_match(
        '/(?:^(bot|java|msie|windows-live-social-object-extractor)|\((java|[' .
        'a-z]\:[0-9]{2,}))/',
    $UANoSpace), 'Unauthorised'); // 2017.02.03

    $Trigger(preg_match('~(?:[^a-z]|^)(?:cu|pe)rl(?:[^a-z]|$)~', $UANoSpace), 'Unauthorised'); // 2017.02.25

    $Trigger(preg_match(
        '/(?:^(go 1)|m(ovable type|msie 999\.1))/',
    $UA), 'Unauthorised'); // 2017.02.03

    $Trigger(preg_match('/(?:internet explorer)/', $UA), 'Hostile / Fake IE'); // 2017.02.03
    $Trigger(preg_match('/(?:MSIECrawler)/', $CIDRAM['BlockInfo']['UA']), 'Hostile / Fake IE', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match('~opera/[0-8]\.~', $UA), 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'http://www.mozilla/') !== false, 'Abusive UA'); // 2017.02.25
    $Trigger(strpos($UA, 'movabletype/3.3') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla 4.0') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/0.') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/1.') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/2.0 (compatible; ask/teoma)') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/3.0 (compatible;)') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/4.0 (compatible; ics 1.2.105)') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/4.0 (compatible; msie 6.0; windows xp)') !== false, 'Bad UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/4.0+(compatible;+') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'mozilla/4.76 [ru] (x11; U; sunos 5.7 sun4u)') !== false, 'Bot UA'); // 2017.02.25
    $Trigger(strpos($UA, 'php /') !== false, 'Bot UA'); // 2017.02.25

    $Trigger(preg_match(
        '/(?:drop ?table|(_table|assert|co(de|ntents)|dotnet_load|e(cho|regi' .
        '|scape|val|x(ec(utable)?|ists)?)|f(ile|unction)|g(et(c(sv)?|ss?)|zi' .
        'nflate)|if|[ints]able|nt|open|p(lace|uts)|re(ad|store)|s(chema|tart' .
        '|ystem)|thru|un(ction|serialize)|w(hil|rit)e)\(|database\(\))/',
    $UA), 'UAEX'); // 2017.02.02

    $Trigger(preg_match("\x01" . '(?:[./]seo|seo/)' . "\x01", $UANoSpace), 'SEO UA'); // 2017.01.08

    $Trigger(strpos($UA, 'bittorrent') !== false, 'Bad context (not a bittorrent hub)'); // 2017.02.25

    $Trigger(empty($CIDRAM['Ignore']['Seznam.cz']) && strpos($UANoSpace, 'seznambot') !== false, 'Seznam.cz'); // 2017.02.02 (ASNs 43037, 200600)

}

$Handle = fopen('php://input', 'rb');
$RawInput = fread($Handle, 1048576);
fclose($Handle);

/**
 * Signatures based on raw input start from here.
 * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
 */
if ($RawInput) {
    $RawInputSafe = strtolower(preg_replace('/[\s\x00-\x1f\x7f-\xff]/', '', $RawInput));

    $Trigger(
        !$is_WP_plugin && preg_match('/[\x00-\x1f\x7f-\xff"#\'-);<>\[\]]/', $RawInput),
        'Non-escaped characters in POST'
    ); // 2017.10.23

    $Trigger(preg_match('/charcode\(88,83,83\)/', $RawInputSafe), 'XSS attempt'); // 2017.03.01
    $Trigger(
        strpos($RawInputSafe, '<?xml') !== false && strpos($RawInputSafe, '<!doctype') !== false && strpos($RawInputSafe, '<!entity') !== false,
    'Suspicious request'); // 2017.03.01
    $Trigger(strpos($RawInputSafe, 'inputbody:action=update&mfbfw') !== false, 'FancyBox exploit attempt'); // 2017.03.01

    $Trigger(!$is_WP_plugin && preg_match(
        '~(?:(lwp-download|fetch)ftp://|(fetch|lwp-download|wget)https?://|<name|method(call|name)|value>)~i',
        $RawInputSafe
    ), 'POST RFI'); // 2017.10.23

    /** Joomla plugins update bypass (POST RFI conflict). */
    $Bypass(
        ($CIDRAM['BlockInfo']['SignatureCount'] - $Infractions) > 0 &&
        strpos($CIDRAM['BlockInfo']['rURI'], 'administrator/') !== false &&
        strpos($CIDRAM['BlockInfo']['WhyReason'], 'POST RFI') !== false,
    'Joomla plugins update bypass (POST RFI conflict)'); // 2017.05.10

    $Trigger(preg_match('~(?:=\[\\\\|%5C\]|\(\)|=%5Bphp%5D|=\[php\]|\\\\\]|=\[%5C|`)~i', $RawInput), 'POST BBCESC/BBCEX/EX'); // 2017.03.01
    $Trigger(preg_match('~/â\\x80¦x\.php~i', $RawInput), 'Probe attempt', '', $InstaBan); // 2017.03.01
    $Trigger(preg_match('~\([\'"](?:zwnobyai|awyoznvu)~', $RawInputSafe), 'Injection attempt', '', $InstaBan); // 2017.03.01
    $Trigger(preg_match('~^/\?-~', $RawInput), 'Hack attempt', '', $InstaBan); // 2017.03.01
    $Trigger(strpos($RawInputSafe, '$_' . '[$' . '__') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.03.01
    $Trigger(strpos($RawInputSafe, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.03.01
    $Trigger(preg_match('~&author_name=(?:%5b|\[)~', $RawInputSafe), 'Bot detection', '', $InstaBan); // 2017.03.01

    $Trigger(preg_match(
        '~(?:%61%(6c%6c%6f%77%5f%75%72%6c%5f%69%6e%63%6c%75%64%65%3d%6f%6e|7' .
        '5%74%6f%5f%70%72%65%70%65%6e%64%5f%66%69%6c%65%3d%70%68%70%3a%2f%2f' .
        '%69%6e%70%75%74)|%63%67%69%2e%(66%6f%72%63%65%5f%72%65%64%69%72%65%' .
        '63%74%3d%30|72%65%64%69%72%65%63%74%5f%73%74%61%74%75%73%5f%65%6e%7' .
        '6%3d%30)|%64%69%73%61%62%6c%65%5f%66%75%6e%63%74%69%6f%6e%73%3d%22%' .
        '22|%6f%70%65%6e%5f%62%61%73%65%64%69%72%3d%6e%6f%6e%65|%73%(61%66%6' .
        '5%5f%6d%6f%64%65%3d%6f%66%66|75%68%6f%73%69%6e%2e%73%69%6d%75%6c%61' .
        '%74%69%6f%6e%3d%6f%6e))~',
    $RawInputSafe), 'Plesk attack'); // 2017.03.01

    $Trigger(preg_match('~(?:6\D*1\D*6\D*6\D*9\D*4\D*7\D*8\D*5)~i', $RawInput), 'Spam attempt'); // 2017.03.01
    $Trigger(preg_match('~//dail' . 'ydigita' . 'ldeals' . '\.info/~i', $RawInput), 'Spam attempt'); // 2017.03.01

    $Trigger((
        strpos($RawInput, 'C6y1F2EA' . '7217PBTL' . '1FlcH98s' . 'Opfo/r1Z' . '76/OKFae') !== false || // 2017.03.04
        strpos($RawInput, 'C4i1F1EA' . '7217PBDF' . '5FlcH77s' . '0pfo/S1t' . '15/13ga') !== false || // 2017.07.21
        strpos($RawInput, 'C6y1F2EA' . '7217PBTL' . '1FlcH98s' . 'Opfo%2Fr' . '1Z76%2FO' . 'KFae') !== false // 2017.10.07
    ), 'Compromised API key used in brute-force attacks.');

}
