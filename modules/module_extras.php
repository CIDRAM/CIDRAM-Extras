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
 * This file: Optional security extras module (last modified: 2017.01.09).
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

/** Directory traversal protection. */
$Trigger(
    preg_match("\x01" . '(?:/|%5[cf])\.{2,}(?:/|%5[cf])' . "\x01i", str_replace("\\", '/', $CIDRAM['BlockInfo']['rURI'])),
    'Traversal attack'
); // 2017.01.08

/** Detect bad/dangerous/malformed requests. */
$Trigger(
    preg_match("\x01" . '(?:(/|%5[cf])\.(/|%5[cf])|(/|%5[cf]){3,}|[\x00-\x1f\x7f])' . "\x01i", str_replace("\\", '/', $CIDRAM['BlockInfo']['rURI'])),
    'Bad request'
); // 2017.01.08

/**
 * Query-based signatures start from here.
 * Please report all false positives to https://github.com/Maikuolan/CIDRAM/issues
 */
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
    $Trigger(preg_match('/p(?:ath|ull)\[?\]/', $QueryNoSpace), 'Hack attempt'); // 2017.01.06
    $Trigger(preg_match('/\'%2[05]/', $_SERVER['QUERY_STRING']), 'Hack attempt'); // 2017.01.05
    $Trigger(preg_match('/\|(?:include|require)/', $QueryNoSpace), 'Hack attempt'); // 2017.01.01
    $Trigger(strpos($Query, 'rm ' . '-rf') !== false, 'Hack attempt', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($QueryNoSpace, "'='") !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, '.php/login.php') !== false, 'Hack attempt'); // 2017.01.05
    $Trigger(strpos($QueryNoSpace, '1http:') !== false, 'Hack attempt'); // 2017.01.01
    $Trigger(strpos($QueryNoSpace, ';c' . 'hmod7' . '77') !== false, 'Hack attempt', '', $InstaBan); // 2017.01.05
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

    $Trigger(preg_match('/pag(?:e|ina)=-/', $QueryNoSpace), 'Probe attempt'); // 2017.01.08
    $Trigger(substr($QueryNoSpace, 0, 1) === '-', 'Probe attempt'); // 2017.01.05

    $Trigger(preg_match(
        '/\[(?:0|[alrw]\]|classes|file|itemid|l(astrss_ap_enabled|oadfile|oc' .
        'alserverfile)|pth|src)/',
    $QueryNoSpace), 'Probe attempt'); // 2017.01.08

    $Trigger(strpos($QueryNoSpace, '+result:') !== false, 'Spam attempt'); // 2017.01.08
    $Trigger(strpos($QueryNoSpace, 'result:+\\') !== false, 'Spam attempt'); // 2017.01.08

    $Trigger(strpos($_SERVER['QUERY_STRING'], '++++') !== false, 'Overflow attempt'); // 2017.01.05

    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $QueryNoSpace), 'XSS attack'); // 2017.01.03

    $Trigger(preg_match('/[\'"`]|[\'"`]/', $QueryNoSpace), 'Pipe detected'); // 2017.01.08

    $Trigger(count($_REQUEST) >= 500, 'Hack attempt', 'Too many request variables sent!'); // 2017.01.01

}

/**
 * UA-based signatures start from here (UA = User Agent).
 * Please report all false positives to https://github.com/Maikuolan/CIDRAM/issues
 */
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
    $Trigger(preg_match(
        '/\$(?:globals|_cookie|_env|_files|_get|_post|_request|_server|_session)/',
    $UANoSpace), 'Command injection'); // 2017.01.08
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

    $Trigger(preg_match('/_(?:cookie|env|files|(ge|pos|reques)t|s(erver|ession))\[/', $UANoSpace), 'Global variable hack'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'globals[') !== false, 'Global variable hack'); // 2017.01.02

    $Trigger(strpos($UANoSpace, '$_' . '[$' . '__') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.02

    $Trigger(preg_match('/0wn[3e]d/', $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(preg_match('/h[4a]c' . 'k(?:e[dr]|ing|t([3e][4a]m|[0o]{2}l))/', $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(preg_match('/Y[EI]$/', $CIDRAM['BlockInfo']['UA']), 'Possible/Suspected hack UA'); // 2017.01.06
    $Trigger(strpos($UA, 'rm ' . '-rf') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UA, 'wordpress ha') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'cha0s') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'fhscan') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'fu' . 'ck') !== false, 'Hack UA', '', $InstaBan); // 2017.01.04
    $Trigger(strpos($UANoSpace, 'if(') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'morfeus') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'r0' . '0t') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'sh' . 'el' . 'l_' . 'ex' . 'ec') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'urldumper') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'whcc/') !== false, 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'zollard') !== false, 'Hack UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, '}__') !== false, 'Hack UA', '', $InstaBan); // 2017.01.02

    $Trigger(strpos($UANoSpace, 'captch') !== false, 'CAPTCHA cracker UA'); // 2017.01.08

    $Trigger(preg_match('/(?:d(iavola|ragostea)|pentru|toata)/', $UANoSpace), 'Probe UA'); // 2017.01.06
    $Trigger(preg_match('/(?:(aihit|casper)bot|mamac(asper|yber))/', $UANoSpace), 'Probe UA', '', $InstaBan); // 2017.01.06
    $Trigger(preg_match(
        '/(?:auto_?http|bigbrother|cybeye|downloaddemon|e(ak01ag9|catch)|i(c' .
        'hiro|ndylibrary|ntelium)|k(angen|mccrew)|libwww-pavuk|m(o(get|zilla' .
        'xyz)|sie6\.0.*deepnet)|net(ants|comber)|p(atchone|aros|lanetwork|ro' .
        'bethenet)|riddler|s(asqia|ledink|noopy|tingbot)|worio|xirio|you?dao' .
        '|zmeu)/',
    $UANoSpace), 'Probe UA'); // 2017.01.08
    $Trigger(strpos($UA, ' obot') !== false, 'Probe UA'); // 2017.01.08
    $Trigger(strpos($UANoSpace, '-agent-') !== false, 'Probe UA'); // 2017.01.06
    $Trigger(substr($UANoSpace, 0, 3) === 'b55', 'Probe UA'); // 2017.01.06

    $Trigger(strpos($UANoSpace, 'wopbot') !== false, 'Bash/Shellshock UA', '', $InstaBan); // 2017.01.06

    $Trigger(preg_match('/ (?:audit|href|quibids )/', $UA), 'Spam UA'); // 2017.01.06
    $Trigger(preg_match('/(?:x(rumer|pymep)|хрумер)/', $UANoSpace), 'Spam UA', '', $InstaBan); // 2017.01.02
    $Trigger(preg_match('/[<\[](?:a|link|url)[ =>\]]/', $UA), 'Spam UA'); // 2017.01.02
    $Trigger(preg_match('/^\.?=/', $UANoSpace), 'Spam UA'); // 2017.01.07
    $Trigger(strpos($UANoSpace, '/how-') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, '>click') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, 'ruru)') !== false, 'Spam UA'); // 2017.01.07
    $Trigger(preg_match(
        '/(?:a(btasty|dwords|llsubmitter|velox)|b(acklink|ad-neighborhood|ds' .
        'm|ea?stiality|iloba|uyessay)|c(asino|ialis|igar|heap|oursework)|d(e' .
        'ltasone|issertation|rugs)|e(ditionyx|roti[ck]|stimatewebstats)|fore' .
        'x|g(abapentin|erifort|inkg?o|uestbook)|h(entai|rbot)|in(cest|come|v' .
        'estment)|jailbreak|k(amagra|eylog)|l(axative|e(sbian|vitra|xap)|i(k' .
        'er\.profile|nkback|nkcheck|pitor)|olita|uxury|lycosa\.se)|m(e(laleu' .
        'ca|nthol)|ixrank)|n(erdybot|eurontin|olvadex)|o(rgasm|utlet)|p(axil' .
        '|harma|illz|lavix|orn|r(0n|opecia|osti))|r(eviewsx|ogaine)|s(ex[xy]' .
        '|hemale|ickseo|limy|tart\.exe|terapred|ynthroid)|t(entacle|[0o]p(ha' .
        'ck|less|sites))|unlock|v(aluationbot|arifort|[1i](agra|olation|tol)' .
        ')|xanax|zdorov)/',
    $UANoSpace), 'Spam UA'); // 2017.01.08

    $Trigger(strpos($UA, ' mra ') !== false, 'mail.ru spam UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'mail.ru') !== false, 'mail.ru spam UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'sputnik') !== false, 'mail.ru spam UA'); // 2017.01.06

    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $UANoSpace), 'XSS attack'); // 2017.01.03

    $Trigger(preg_match(
        '/(?:digger|e((mail)?collector|mail(ex|search|spider|siphon)|xtract(' .
        'ion|or))|iscsystems|microsofturl|oozbot|psycheclone)/',
    $UANoSpace), 'Email havester'); // 2017.01.07
    $Trigger(strpos($UANoSpace, 'email') !== false, 'Possible/Suspected email havester'); // 2017.01.06

    $Trigger($UA === '-', 'Bad UA'); // 2017.01.06
    $Trigger($UANoSpace === 'foo', 'Bad UA'); // 2017.01.06
    $Trigger(preg_match('/%(?:[01][0-9a-f]|2[257]|3[ce]|[57][bd]|[7f]f)/', $UANoSpace), 'Bad UA'); // 2017.01.06

    $Trigger(preg_match(
        '/(?:3mir|a(dmantx|lphaserver|thens|ttache)|collect|d(igout4uagent|s' .
        'arobot)|f(astlwspider|loodgate)|irgrabber|m(agnet|(ajestic|j)12)|nu' .
        'tch|p(ackrat|cbrowser|surf)|r(eaper|sync)|s(hai|[iy]phon)|takeout|w' .
        'olf)/',
    $UANoSpace), 'Bad UA'); // 2017.01.08

    $Trigger(preg_match(
        '/(?:re-?animator|webster)/',
    $UANoSpace), 'Bad UA', '', $InstaBan); // 2017.01.08

    $Trigger(preg_match('/test\'?$/', $UANoSpace), 'Bad UA'); // 2017.01.06
    $Trigger(preg_match('/^[\'"].*[\'"]$/', $UANoSpace), 'Bad UA'); // 2017.01.06
    $Trigger(preg_match('/^\'?test/', $UANoSpace), 'Bad UA'); // 2017.01.06
    $Trigger(strpos($UA, '   ') !== false, 'Bad UA'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'mfibot') !== false, 'Bad UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'tweetmeme') !== false, 'Bad UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'user-agent') !== false, 'Bad UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, '(somename)') !== false, 'Bad UA', '', $InstaBan); // 2017.01.08

    $Trigger(preg_match('/(?:80legs|chinaclaw)/', $UANoSpace), 'Scraper UA', '', $InstaBan); // 2017.01.08
    $Trigger(preg_match('/^(?:abot|spider)/', $UANoSpace), 'Scraper UA'); // 2017.01.07
    $Trigger(strpos($UANoSpace, 'fetch/') !== false, 'Scraper UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'vlc/') !== false, 'Possible/Suspected scraper UA'); // 2017.01.07
    $Trigger(preg_match(
        '/(?:3(60spider|d-ftp)|a(6-indexer|ccelo|ffinity|ghaven|href|ipbot|n' .
        'alyticsseo|pp3lewebkit|rtviper)|b(azqux|ender|inlar|itvo|nf.fr|ogah' .
        'n|oitho|pimagewalker)|c(cbot|entiverse|msworldmap|ommoncrawl|oversc' .
        'out|r4nk|rawlfire|uriousgeorge|ydral)|d(aylife|ebate|igext|(cp|isco' .
        '|ouban|ownload)bot|owjones|tsagent)|e((na|uro|xperi)bot|nvolk|vaal|' .
        'zoom)|f(dm|etch(er.0|or)|ibgen)|g(alaxydownloads|et(download\.ws|ty' .
        '|url11)|slfbot|urujibot)|h(arvest|eritrix|olmes|ttp(fetcher|unit)|t' .
        'track)|i(mage(.fetcher|walker)|n(agist|docom|fluencebot)|track)|j(a' .
        'karta|ike)|k(ey(wenbot|wordsearchtool)|imengi|kman)|l(arbin|ink(dex' .
        '|walker)|iperhey|(t|ush)bot)|m(a(hiti|honie|ttters)|iabot|lbot|ormo' .
        'r|ot-v980|rchrome|ulticrawler)|n(e(ofonie|tseer|wsbot)|ineconnectio' .
        'ns)|o(fflinenavigator|odlebot)|p(age(fetch|gett|_verifi)er|anscient' .
        '|ath2|ic(grabber|s|tsnapshot|turefinder)|i(pl|xmatch|xray)|oe-compo' .
        'nent-client-|owermarks|roximic|(s|ure)bot|urity)|qqdownload|r(ankiv' .
        'abot|ebi-shoveler|everseget|ganalytics|ocketcrawler)|s(afeassign|bi' .
        'der|bl[.-]bot|crape|emrush|eo(eng|profiler|stat)|istrix|ite(bot|int' .
        'el)|n[iy]per|olomono|pbot|pyder|search|webot)|t(-h-u-n|agsdir|ineye' .
        '|opseo|raumacadx|urnitinbot)|up(downer|ictobot)|v(bseo|isbot|oyager' .
        ')|w(arebay|auuu|bsearchbot|eb(alta|capture|download|ripper)|ikio|in' .
        'dows(3|seven)|inhttp|khtmlto|orldbot|otbox)|xtractorpro|yoofind)/',
    $UANoSpace), 'Scraper UA'); // 2017.01.08
    $Trigger(preg_match(
        '/(?:c(hilkat|copyright)|flipboard|g(ooglealerts|rub)|python)/',
    $UANoSpace), 'Possible/Suspected scraper UA'); // 2017.01.07

    $Trigger(preg_match(
        '/(?:cncdialer|d(esktopsmiley|s_juicyaccess)|foxy.1|genieo|hotbar|ic' .
        'afe|m(utant|yway)|o(otkit|ssproxy)|qqpinyinsetup|si(cent|mbar)|tenc' .
        'enttraveler|zeus)/',
    $UANoSpace), 'Malware UA'); // 2017.01.08

    $Trigger(preg_match(
        '/(?:200please|awcheck|c(entric|omment|razywebcrawler)|d(ataprovider' .
        '|ot(bot|comdotnet|netdotcom))|mo(reover|z\.com)|nextgensearchbot|p(' .
        'agesinventory|rofiler)|r(6_|adian6|ogerbot)|s(earchmetricsbot|eo(hu' .
        'nt|kicks|mon|tool)|phider)|vagabondo|w(ebmastercoffee|ise-guys))/',
    $UANoSpace), 'SEO UA'); // 2017.01.08

    $Trigger(preg_match("\x01" . '(?:[./]seo|seo/)' . "\x01", $UANoSpace), 'SEO UA'); // 2017.01.08

}
