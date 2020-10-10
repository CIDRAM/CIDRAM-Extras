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
 * This file: Optional user agents module (last modified: 2020.09.20).
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

/** Defining as closure for later recall (no params; no return value). */
$CIDRAM['ModuleResCache'][$Module] = function () use (&$CIDRAM) {
    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /**
     * UA-based signatures start from here (UA = User Agent).
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if (!$CIDRAM['BlockInfo']['UA'] || $Trigger(strlen($CIDRAM['BlockInfo']['UA']) > 4096, 'Bad UA', 'User agent string is too long!')) {
        return;
    }

    /** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
    $InstaBan = ['Options' => ['TrackTime' => 31536000, 'TrackCount' => 1000]];

    $UA = str_replace("\\", '/', strtolower(urldecode($CIDRAM['BlockInfo']['UA'])));
    $UANoSpace = preg_replace('/\s/', '', $UA);

    $Trigger(preg_match('/\((?:["\']{2})?\)/', $UANoSpace), 'UA command injection'); // 2017.01.02

    $Trigger(preg_match(
        '/(?:_once|able|as(c|hes|sert)|c(hr|ode|ontents)|e(cho|regi|scape|val)|ex' .
        '(ec|ists)?|f(ile|late|unction)|get(c|csv|ss?)?|i(f|nclude)|len(gth)?|ope' .
        'n|p(ress|lace|lode|uts)|print(f|_r)?|re(ad|place|quire|store)|rot13|s(ta' .
        'rt|ystem)|w(hil|rit)e)["\':(\[{<$]/',
    $UANoSpace), 'UA command injection'); // 2017.01.20

    $Trigger(preg_match(
        '/\$(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))/',
    $UANoSpace), 'UA command injection'); // 2017.01.13

    $Trigger(preg_match('/http_(?:cmd|sum)/', $UANoSpace), 'UA command injection'); // 2017.01.02
    $Trigger(preg_match('/pa(?:rse_ini_file|ssthru)/', $UANoSpace), 'UA command injection'); // 2017.01.02
    $Trigger(preg_match('/rewrite(?:cond|rule)/', $UANoSpace), 'UA command injection'); // 2017.01.02
    $Trigger(preg_match('/u(?:nserialize|ploadedfile)/', $UANoSpace), 'UA command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'dotnet_load') !== false, 'UA command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'execcgi') !== false, 'UA command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'move_uploaded_file') !== false, 'UA command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'symlink') !== false, 'UA command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, 'tmp_name') !== false, 'UA command injection'); // 2017.01.02
    $Trigger(strpos($UANoSpace, '_contents') !== false, 'UA command injection'); // 2017.01.02

    $Trigger(preg_match('/%(?:0[0-8bcef]|1)/i', $CIDRAM['BlockInfo']['UA']), 'Non-printable characters in UA'); // 2017.01.02

    $Trigger(preg_match(
        '/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/',
    $UANoSpace), 'UA script injection'); // 2017.01.08

    $Trigger(preg_match(
        '/(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))\[/',
    $UANoSpace), 'UA global variable hack'); // 2017.01.13

    $Trigger(strpos($UANoSpace, '$_' . '[$' . '__') !== false, 'UA shell upload attempt', '', $InstaBan); // 2017.01.02
    $Trigger(strpos($UANoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'UA shell upload attempt', '', $InstaBan); // 2017.01.02

    $Trigger(preg_match('/0wn[3e]d/', $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.01.06
    $Trigger(preg_match('/:(\{[\w]:|[\w\d][;:]\})/', $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.01.20
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
        '~cha0s|dkemdif.\d|fhscan|f' . 'uck|havij|jdatabasedrivermysqli|morfeus|urldumper|xmlset_roodkcable|zollard~',
    $UANoSpace), 'Hack UA', '', $InstaBan); // 2019.06.23

    $Trigger(strpos($UA, 'select ') !== false, 'UASQLi'); // 2017.02.25

    $Trigger(strpos($UANoSpace, 'captch') !== false, 'CAPTCHA cracker UA'); // 2017.01.08

    $Trigger(preg_match('~(?:(aihit|casper)bot|mamac(asper|yber)|mozilla/0)~', $UANoSpace), 'Probe UA', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match(
        '~(?:^b55|-agent-|auto_?http|bigbrother|cybeye|d(?:(?:iavol|ragoste)a|own' .
        'loaddemon)|e(?:ak01ag9|catch)|i(?:ndylibrary|ntelium)|k(?:angen|mccrew)|' .
        'libwww-pavuk|m(?:o(?:get|zillaxyz)|sie6\.0.*deepnet)|n(?:et(?:ants|combe' .
        'r)|s8/0\.9\.6)|p(?:atchone|aros|entru|lanetwork|robe)|riddler|s(?:asqia|' .
        'ledink|noopy|tingbot)|toata|updown_tester|w(?:hitehataviator|orio)|xirio' .
        '|zmeu)~',
    $UANoSpace), 'Probe UA'); // 2019.03.04

    $Trigger(preg_match('/(?: obot|ie 5\.5 compatible browser)/', $UA), 'Probe UA'); // 2017.02.02
    $Trigger(preg_match('~(?:photon/|pogs/2\.0)~', $UANoSpace), 'Probe UA'); // 2018.06.24

    $Trigger(strpos($UANoSpace, 'wopbot') !== false, 'Bash/Shellshock UA', '', $InstaBan); // 2017.01.06

    $Trigger(preg_match('/(?:x(rumer|pymep)|хрумер)/', $UANoSpace), 'Spam UA', '', $InstaBan); // 2017.01.02
    $Trigger(preg_match('/[<\[](?:a|link|url)[ =>\]]/', $UA), 'Spam UA'); // 2017.01.02
    $Trigger(preg_match('/^\.?=/', $UANoSpace), 'Spam UA'); // 2017.01.07
    $Trigger(strpos($UANoSpace, '/how-') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, '>click') !== false, 'Spam UA'); // 2017.01.04
    $Trigger(strpos($UANoSpace, 'ruru)') !== false, 'Spam UA'); // 2017.01.07

    $Trigger(preg_match(
        '/(?:a(?:btasty|dwords|llsubmitter|velox)|b(?:acklink|ad-neighborhood|dsm' .
        '|ea?stiality|iloba|ork-edition|uyessay)|c(?:asino|ialis|igar|heap|oursew' .
        'ork)|deltasone|dissertation|drugs|editionyx|eroti[ck]|estimatewebstats|f' .
        'orex|funbot|g(?:abapentin|erifort|inkg?o|uestbook)|hentai|honeybee|hrbot' .
        '|in(?:cest|come|vestment)|jailbreak|kamagra|keylog|l(?:axative|esbian|ev' .
        'itra|exap|i(?:ker\.profile|nk(?:ba|che)ck|pitor)|olita|uxury|ycosa\.se)|' .
        'm(?:ail\.ru|e(?:laleuca|nthol)|ixrank|rie8pack)|n(?:erdybot|etzcheckbot|' .
        'eurontin|olvadex)|orgasm|outlet|p(?:axil|harma|illz|lavix|orn|r0n|ropeci' .
        'a|rosti)|reviewsx|rogaine|s(?:ex[xy]|hemale|ickseo|limy|putnik|tart\.exe' .
        '|terapred|ynthroid)|t(?:entacle|[0o]p(?:hack|less|sites))|u(?:01-2|nlock' .
        ')|v(?:(?:aluation|oila)bot|arifort|[1i](?:agra|olation|tol))|warifort|xa' .
        'nax|zdorov)/',
    $UANoSpace), 'Spam UA'); // 2018.12.15

    $Trigger(preg_match(
        '/(?: (audit|href|mra |quibids )|\(build 5339\))/',
    $UA), 'Spam UA'); // 2017.02.02

    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $UANoSpace), 'XSS attack'); // 2017.01.03
    $Trigger(strpos($UANoSpace, '`') !== false, 'Execution attempt'); // 2017.01.13

    $Trigger(preg_match(
        '/(?:digger|e(?:mail)?collector|email(?:ex|search|spider|siphon)|extract(' .
        '?:ion|or)|iscsystems|microsofturl|oozbot|psycheclone)/',
    $UANoSpace), 'Email havester'); // 2018.04.23

    $Trigger(strpos($UANoSpace, 'email') !== false, 'Possible/Suspected email havester'); // 2017.01.06

    $Trigger(preg_match('/%(?:[01][\da-f]|2[257]|3[ce]|[57][bd]|[7f]f)/', $UANoSpace), 'Bad UA'); // 2017.01.06

    $Trigger(preg_match(
        '/(?:loadimpact|re-?animator|root|webster)/',
    $UANoSpace), 'Banned UA', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match('/test\'?$/', $UANoSpace), 'Banned UA'); // 2017.02.02
    $Trigger(preg_match('/^(?:\'?test|-|default|foo)/', $UANoSpace), 'Banned UA'); // 2017.02.02
    $Trigger(preg_match('/^[\'"].*[\'"]$/', $UANoSpace), 'Banned UA'); // 2017.02.02
    $Trigger(strpos($UA, '   ') !== false, 'Banned UA'); // 2017.02.02
    $Trigger(strpos($UANoSpace, '(somename)') !== false, 'Banned UA', '', $InstaBan); // 2017.02.02

    $Trigger(preg_match(
        '~_sitemapper|3mir|a(?:boundex|dmantx|dnormcrawler|dvbot|lphaserver|thens' .
        '|ttache)|blekko|blogsnowbot|bytespider|cmscrawler|co(?:ccoc|llect|modo-webinspector' .
        '-crawler|mpspy)|crawler(?:4j|\.feedback)|d(?:atacha|igout4uagent|ioscout' .
        '|kimrepbot|sarobot)|easou|exabot|f(?:astenterprisecrawler|astlwspider|in' .
        'd?bot|indlinks|loodgate|r[_-]?crawler)|hrcrawler|hubspot|i(?:mrbot|ntegr' .
        'omedb|p-?web-?crawler|rcsearch|rgrabber)|jadynavebot|komodiabot|lightspe' .
        'ed|linguee|linkpad|m(?:ajestic12|agnet|auibot|eanpath|entormate|fibot|ig' .
        'nify|j12)|nutch|omgilibot|p(?:ackrat|cbrowser|lukkie|surf)|reaper|rsync|' .
        's(?:aidwot|alad|cspider|ees\.co|hai|iteexplorer|[iy]phon|truct\.it|uppor' .
        't\.wordpress\.com|ystemscrawler)|takeout|tasapspider|tweetmeme|user-agen' .
        't|visaduhoc|vonchimpenfurlr|webtarantula|wolf|y(?:acy|isouspider|[ry]spi' .
        'der|unrang|unyun)|zoominfobot~',
    $UANoSpace), 'Banned UA'); // 2019.10.01

    $Trigger(preg_match(
        '/^wp-iphone$/',
    $UANoSpace), 'Banned UA'); // 2017.12.14

    $Trigger(preg_match('/(?:80legs|chinaclaw)/', $UANoSpace), 'Scraper UA', '', $InstaBan); // 2017.01.08

    $Trigger(preg_match(
        '~chilkat|ccopyright|fetch/|flipboard|googlealerts|grub|indeedbot|python|' .
        'quick-crawler|scrapinghub|ttd-content|^(?:abot|spider)~',
    $UANoSpace), 'Scraper UA'); // 2020.04.05

    $Trigger(preg_match(
        '/(?:007ac9|200please|360spider|3d-ftp|a(?:6-indexer|ccelo|ffinity|ghaven' .
        '|href|ipbot|naly(?:ticsseo|zer)|pp3lewebkit|rtviper|wcheck)|b(' .
        '?:azqux|ender|inlar|itvo|ixo|lex|nf.fr|ogahn|oitho|pimagewalker)|c(?:cbo' .
        't|ent(?:iverse|ric)|ityreview|msworldmap|omment|ommoncrawl|overscout|r4n' .
        'k|rawl(?:erbotalpha|fire)|razywebcrawler|uriousgeorge|ydral)|d(?:ataprov' .
        'ider|atenbank|aylife|ebate|igext|(?:cp|isco|ot|ouban|ownload)bot|otcomdo' .
        'tnet|otnetdotcom|owjones|tsagent)|e(?:(?:na|uro|xperi)bot|nvolk|vaal|zoo' .
        'm)|f(?:dm|etch(?:er.0|or)|ibgen)|g(?:alaxydownloads|et(?:download\.ws|ty' .
        '|url11)|slfbot|umgum|urujibot)|h(?:arvest|eritrix|olmes|ttp(?:fetcher|un' .
        'it)|ttrack)|i(?:mage(?:.fetcher|walker)|linkscrawler|nagist|ndocom|nflue' .
        'ncebot|track)|jakarta|jike|k(?:eywenbot|eywordsearchtool|imengi|kman)|l(' .
        '?:arbin|ink(?:dex|walker)|iperhey|(?:t|ush)bot)|m(?:ahiti|ahonie|attters' .
        '|egaindex|iabot|lbot|oreover|ormor|ot-v980|oz\.com|rchrome|ulticrawler)|' .
        'n(?:eofonie|etestate|ewsbot|extgensearchbot|ineconnections)|o(?:afcrawl|' .
        'fflinenavigator|odlebot|ptimizer)|p(?:age(?:fetch|gett|_verifi)er|agesin' .
        'ventory|anscient|ath2|ic(?:grabber|s|tsnapshot|turefinder)|i(?:pl|xmatch' .
        '|xray)|oe-component-client-|owermarks|rofiler|roximic|(?:s|ure)bot|urity' .
        ')|qqdownload|r(?:6_|adian6|ankivabot|ebi-shoveler|everseget|ganalytics|o' .
        'cketcrawler|ogerbot|sscrawl|ulinki)|s(?:afeassign|bider|bl[.-]bot|crap[e' .
        'y]|earchmetricsbot|emrush|eo(?:bulls|eng|hunt|kicks|mon|profiler|stat|to' .
        'ol)|istrix|ite(?:bot|intel)|n[iy]per|olomono|pbot|p(?:hi|y)der|search|we' .
        'bot)|t(?:-h-u-n|agsdir|ineye|opseo|raumacadx|urnitinbot)|u(?:12bot|p(?:d' .
        'owner|ictobot))|v(?:agabondo|bseo|isbot|oyager)|w(?:arebay|auuu|bsearchb' .
        'ot|eb(?:alta|capture|download|mastercoffee|meup|ripper)|ikio|indows(?:3|' .
        'seven)|inhttp|ise-guys|khtmlto|orldbot|otbox)|xtractorpro|yoofind)/',
    $UANoSpace), 'Backlink/SEO/Scraper UA'); // 2018.07.10 mod 2020.09.20

    $Trigger(preg_match('/(?:brandwatch|magpie)/', $UANoSpace), 'Snoop UA', '', $InstaBan); // 2017.01.13
    $Trigger(strpos($UANoSpace, 'catch') !== false, 'Risky UA'); // 2017.01.13

    $Trigger(preg_match('/(?:anonymous|vpngate)/', $UANoSpace), 'Proxy UA'); // 2017.01.13

    $Trigger(preg_match(
        '/(?:360se|cncdialer|desktopsmiley|ds_juicyaccess|foxy.1|genieo|hotbar|ic' .
        'afe|magicbrowser|mutant|myway|ootkit|ossproxy|qqpinyinsetup|sicent|simba' .
        'r|tencenttraveler|theworld|wsr-agent|zeus)/',
    $UANoSpace), 'Malware UA'); // 2017.04.23

    $Trigger(preg_match(
        '~\.buzz|a(?:bonti|ccserver|cme.spider|nyevent-http|ppengine)|b(?:abbar\.' .
        'tech|igbozz|lackbird|logsearch|logbot|salsa)|c(?:atexplorador|lickagy|li' .
        'qzbot|ontextad|orporama|rowsnest|yberpatrol)|d(?:bot/|le_spider|omainapp' .
        'ender|umprendertree)|flightdeckreportsbot|gimme60|googlebenjojo|http-?(?' .
        ':agent|client)|internetcensus|ips-agent|isitwp|k2spider|kemvi|lexxebot|l' .
        'ivelapbot|lwp|macinroyprivacyauditors|masscan|metaintelligence|n(?:etcra' .
        'ft|ettrapport|icebot|mapscriptingengine|rsbot)|p(?:4bot|4load|acrawler|a' .
        'geglimpse|arsijoo|egasusmonitoring|hantomjs|hpcrawl|ingdom|rlog)|r(?:are' .
        'lyused|obo(?:cop|spider)|yze)|s(?:can\.lol|creener|itedomain|mut|nap(?:p' .
        'review)?bot|oapclient|ocial(?:ayer|searcher)|oso|pyglass|quider|treetbot' .
        '|ynapse)|tweezler|urlappendbot|w(?:asalive|atchmouse|eb(?:-monitoring|bo' .
        't|masteraid|money|thumbnail)|hatweb|ikiapiary|in(?:http|inet)|maid\.com|' .
        'sr-agent|wwtype)|xenu|xovi|zibber|zurichfinancialservices|^m$|(?:\W|^)(?' .
        ':cu|pe)rl(?:\W|$)~',
    $UANoSpace), 'Unauthorised'); // 2020.03.02

    $Trigger(preg_match(
        '~^(?:bot|java|msie|windows-live-social-object-extractor)|\((?:java|\w\:\d{2,})~',
    $UANoSpace), 'Fake UA'); // 2019.06.30

    $Trigger(preg_match(
        '~^go +\d|movable type|msie ?(?:\d{3,}|[2-9]\d|[0-8]\.)~i',
    $UA), 'Fake UA'); // 2019.06.30

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

    $Trigger(preg_match('~(?:[./]seo|seo/)~', $UANoSpace), 'SEO UA'); // 2018.07.10

    $Trigger(strpos($UA, 'bittorrent') !== false, 'Bad context (not a bittorrent hub)'); // 2017.02.25

    /** Reporting. */
    if (strpos($CIDRAM['BlockInfo']['WhyReason'], 'UA command injection') !== false) {
        $CIDRAM['Reporter']->report([15], ['Command injection detected in user agent.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'UA script injection') !== false) {
        $CIDRAM['Reporter']->report([15], ['Script injection detected in user agent.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'UA global variable hack') !== false) {
        $CIDRAM['Reporter']->report([15], ['Globvar hack detected in user agent.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'UA shell upload attempt') !== false) {
        $CIDRAM['Reporter']->report([15], ['Shell upload attempt detected in user agent.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Hack UA') !== false) {
        $CIDRAM['Reporter']->report([15], ['Hack identifier detected in user agent.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'UASQLi') !== false) {
        $CIDRAM['Reporter']->report([16], ['SQLi attempt detected in user agent.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'CAPTCHA cracker UA') !== false) {
        $CIDRAM['Reporter']->report([19], ['CAPTCHA cracker detected.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Probe UA') !== false) {
        $CIDRAM['Reporter']->report([19], ['Probe detected.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Bash/Shellshock UA') !== false) {
        $CIDRAM['Reporter']->report([16], ['Bash/Shellshock attempt detected via user agent.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Spam UA') !== false) {
        $CIDRAM['Reporter']->report([19], ['Spambot detected.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Email havester') !== false) {
        $CIDRAM['Reporter']->report([19], ['Email havester detected.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Execution attempt') !== false) {
        $CIDRAM['Reporter']->report([15], ['Attempted to push shell commands via user agent header.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'XSS attack') !== false) {
        $CIDRAM['Reporter']->report([15], ['Attempted to push XSS via user agent header.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Banned UA') !== false) {
        $CIDRAM['Reporter']->report([19], ['Misbehaving bot detected at this address.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Scraper UA') !== false) {
        $CIDRAM['Reporter']->report([19], ['Scraper detected at this address.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Malware UA') !== false) {
        $CIDRAM['Reporter']->report([19], ['User agent cited by malware detected at this address.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Fake UA') !== false) {
        $CIDRAM['Reporter']->report([19], ['Faked user agent detected.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'UAEX') !== false) {
        $CIDRAM['Reporter']->report([19], ['Detected command execution via user agent header.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'bittorrent') !== false) {
        $CIDRAM['Reporter']->report([4, 19], ['BitTorrent user agent seen at HTTP server endpoint (possible flood/DDoS attempt).'], $CIDRAM['BlockInfo']['IPAddr']);
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
