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
 * This file: Optional user agents module (last modified: 2018.07.16).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
$InstaBan = ['Options' => ['TrackTime' => 31536000, 'TrackCount' => 1000]];

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
        '/(?:cha0s|f(hscan|uck)|havij|jdatabasedrivermysqli|morfeus|urldumper|xmlset_roodkcable|zollard)/',
    $UANoSpace), 'Hack UA', '', $InstaBan); // 2017.02.25

    $Trigger(strpos($UA, 'select ') !== false, 'UASQLi'); // 2017.02.25

    $Trigger(strpos($UANoSpace, 'captch') !== false, 'CAPTCHA cracker UA'); // 2017.01.08

    $Trigger(preg_match('~(?:(aihit|casper)bot|mamac(asper|yber)|mozilla/0)~', $UANoSpace), 'Probe UA', '', $InstaBan); // 2017.02.25

    $Trigger(preg_match(
        '~(?:^b55|-agent-|auto_?http|bigbrother|cybeye|d(?:(?:iavol|ragoste)' .
        'a|ownloaddemon)|e(?:ak01ag9|catch)|i(?:chiro|ndylibrary|ntelium)|k(' .
        '?:angen|mccrew)|libwww-pavuk|m(?:o(?:get|zillaxyz)|sie6\.0.*deepnet' .
        ')|n(?:et(?:ants|comber)|s8/0\.9\.6)|p(?:atchone|aros|entru|lanetwor' .
        'k|robe)|riddler|s(?:asqia|ledink|noopy|tingbot)|toata|updown_tester' .
        '|w(?:hitehataviator|orio)|xirio|you?dao|zmeu)~',
    $UANoSpace), 'Probe UA'); // 2018.05.01

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
        '/(?:a(?:btasty|dwords|llsubmitter|velox)|b(?:acklink|ad-neighborhoo' .
        'd|dsm|ea?stiality|iloba|ork-edition|uyessay)|c(?:asino|ialis|igar|h' .
        'eap|oursework)|d(?:eltasone|issertation|rugs)|e(?:ditionyx|roti[ck]' .
        '|stimatewebstats)|forex|funbot|g(?:abapentin|erifort|inkg?o|uestboo' .
        'k)|hentai|hrbot|in(?:cest|come|vestment)|jailbreak|kamagra|keylog|l' .
        '(?:axative|esbian|evitra|exap|i(?:ker\.profile|nk(?:ba|che)ck|pitor' .
        ')|olita|uxury|ycosa\.se)|m(?:ail\.ru|e(?:laleuca|nthol)|ixrank|rie8' .
        'pack)|n(?:erdybot|etzcheckbot|eurontin|olvadex)|orgasm|outlet|p(?:a' .
        'xil|harma|illz|lavix|orn|r0n|ropecia|rosti)|reviewsx|rogaine|s(?:ex' .
        '[xy]|hemale|ickseo|limy|putnik|tart\.exe|terapred|ynthroid)|t(?:ent' .
        'acle|[0o]p(?:hack|less|sites))|u(?:01-2|nlock)|v(?:(?:aluation|oila' .
        ')bot|arifort|[1i](?:agra|olation|tol))|warifort|xanax|zdorov)/',
    $UANoSpace), 'Spam UA'); // 2018.05.01

    $Trigger(preg_match(
        '/(?: (audit|href|mra |quibids )|\(build 5339\))/',
    $UA), 'Spam UA'); // 2017.02.02

    $Trigger(preg_match('/[\'"`]\+[\'"`]/', $UANoSpace), 'XSS attack'); // 2017.01.03
    $Trigger(strpos($UANoSpace, '`') !== false, 'Execution attempt'); // 2017.01.13

    $Trigger(preg_match(
        '/(?:digger|e(?:mail)?collector|email(?:ex|search|spider|siphon)|ext' .
        'ract(?:ion|or)|iscsystems|microsofturl|oozbot|psycheclone)/',
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
        '/(?:_sitemapper|3mir|a(?:boundex|dmantx|dnormcrawler|dvbot|lphaserv' .
        'er|thens|ttache)|blekko|blogsnowbot|cmscrawler|co(?:ccoc|llect|modo' .
        '-webinspector-crawler|mpspy)|crawler(?:4j|\.feedback)|d(?:atacha|ig' .
        'out4uagent|ioscout|kimrepbot|sarobot)|easou|exabot|f(?:astenterpris' .
        'ecrawler|astlwspider|ind?bot|indlinks|loodgate|r[_-]?crawler)|grape' .
        'shot|hrcrawler|hubspot|i(?:mrbot|ntegromedb|p-?web-?crawler|rcsearc' .
        'h|rgrabber)|jadynavebot|komodiabot|linguee|linkpad|m(?:ajestic12|ag' .
        'net|auibot|eanpath|entormate|fibot|ignify|j12)|nutch|omgilibot|p(?:' .
        'ackrat|cbrowser|lukkie|surf)|reaper|rsync|s(?:aidwot|alad|cspider|e' .
        'es\.co|hai|iteexplorer|[iy]phon|truct\.it|upport\.wordpress\.com)|t' .
        'akeout|tasapspider|tweetmeme|user-agent|visaduhoc|vonchimpenfurlr|w' .
        'ebtarantula|wolf|y(?:acy|isouspider|[ry]spider|unrang|unyun)|zoomin' .
        'fobot)/',
    $UANoSpace), 'Banned UA'); // 2018.04.23

    $Trigger(preg_match(
        '/^wp-iphone$/',
    $UANoSpace), 'Banned UA'); // 2017.12.14

    $Trigger(preg_match('/(?:80legs|chinaclaw)/', $UANoSpace), 'Scraper UA', '', $InstaBan); // 2017.01.08
    $Trigger(preg_match('/^(?:abot|spider)/', $UANoSpace), 'Scraper UA'); // 2017.01.07
    $Trigger(strpos($UANoSpace, 'fetch/') !== false, 'Scraper UA'); // 2017.01.06
    $Trigger(strpos($UANoSpace, 'vlc/') !== false, 'Possible/Suspected scraper UA'); // 2017.01.07

    $Trigger(preg_match(
        '/(?:007ac9|200please|360spider|3d-ftp|a(?:6-indexer|ccelo|ffinity|g' .
        'haven|href|ipbot|naly(?:ticsseo|zer)|pp3lewebkit|rchivebot|rtviper|' .
        'wcheck)|b(?:azqux|ender|inlar|itvo|ixo|lex|nf.fr|ogahn|oitho|pimage' .
        'walker)|c(?:cbot|ent(?:iverse|ric)|ityreview|msworldmap|omment|ommo' .
        'ncrawl|overscout|r4nk|rawl(?:erbotalpha|fire)|razywebcrawler|urious' .
        'george|ydral)|d(?:ataprovider|atenbank|aylife|ebate|igext|(?:cp|isc' .
        'o|ot|ouban|ownload)bot|otcomdotnet|otnetdotcom|owjones|tsagent)|e(?' .
        ':(?:na|uro|xperi)bot|nvolk|vaal|zoom)|f(?:dm|etch(?:er.0|or)|ibgen)' .
        '|g(?:alaxydownloads|et(?:download\.ws|ty|url11)|slfbot|umgum|urujib' .
        'ot)|h(?:arvest|eritrix|olmes|ttp(?:fetcher|unit)|ttrack)|i(?:mage(?' .
        ':.fetcher|walker)|linkscrawler|nagist|ndocom|nfluencebot|track)|jak' .
        'arta|jike|k(?:eywenbot|eywordsearchtool|imengi|kman)|l(?:arbin|ink(' .
        '?:dex|walker)|iperhey|(?:t|ush)bot)|m(?:ahiti|ahonie|attters|egaind' .
        'ex|iabot|lbot|oreover|ormor|ot-v980|oz\.com|rchrome|ulticrawler)|n(' .
        '?:eofonie|etestate|ewsbot|extgensearchbot|ineconnections)|o(?:afcra' .
        'wl|fflinenavigator|odlebot|ptimizer)|p(?:age(?:fetch|gett|_verifi)e' .
        'r|agesinventory|anscient|ath2|ic(?:grabber|s|tsnapshot|turefinder)|' .
        'i(?:pl|xmatch|xray)|oe-component-client-|owermarks|rofiler|roximic|' .
        '(?:s|ure)bot|urity)|qqdownload|r(?:6_|adian6|ankivabot|ebi-shoveler' .
        '|everseget|ganalytics|ocketcrawler|ogerbot|sscrawl|ulinki)|s(?:afea' .
        'ssign|bider|bl[.-]bot|crap[ey]|earchmetricsbot|emrush|eo(?:bulls|en' .
        'g|hunt|kicks|mon|profiler|stat|tool)|istrix|ite(?:bot|intel)|n[iy]p' .
        'er|olomono|pbot|p(?:hi|y)der|search|webot)|t(?:-h-u-n|agsdir|ineye|' .
        'opseo|raumacadx|urnitinbot)|u(?:12bot|p(?:downer|ictobot))|v(?:agab' .
        'ondo|bseo|isbot|oyager)|w(?:arebay|auuu|bsearchbot|eb(?:alta|captur' .
        'e|download|mastercoffee|meup|ripper)|ikio|indows(?:3|seven)|inhttp|' .
        'ise-guys|khtmlto|orldbot|otbox)|xtractorpro|yoofind)/',
    $UANoSpace), 'Backlink/SEO/Scraper UA'); // 2018.07.10

    $Trigger(preg_match('/quick-crawler|scrapinghub/', $UANoSpace), 'Scraper UA'); // 2018.07.16

    $Trigger(preg_match(
        '/(?:chilkat|ccopyright|flipboard|googlealerts|grub|indeedbot|python)/',
    $UANoSpace), 'Possible/Suspected scraper UA'); // 2017.04.23

    $Trigger(preg_match('/(?:brandwatch|magpie)/', $UANoSpace), 'Snoop UA', '', $InstaBan); // 2017.01.13
    $Trigger(strpos($UANoSpace, 'catch') !== false, 'Risky UA'); // 2017.01.13

    $Trigger(preg_match('/(?:anonymous|vpngate)/', $UANoSpace), 'Proxy UA'); // 2017.01.13

    $Trigger(preg_match(
        '/(?:360se|cncdialer|desktopsmiley|ds_juicyaccess|foxy.1|genieo|hotb' .
        'ar|icafe|magicbrowser|mutant|myway|ootkit|ossproxy|qqpinyinsetup|si' .
        'cent|simbar|tencenttraveler|theworld|wsr-agent|zeus)/',
    $UANoSpace), 'Malware UA'); // 2017.04.23

    $Trigger(preg_match(
        '~(?:\.buzz|a(?:bonti|ccserver|cme.spider|nyevent-http|ppengine)|b(?' .
        ':igbozz|lackbird|logsearch|logbot|salsa)|c(?:atexplorador|lickagy|l' .
        'iqzbot|ontextad|orporama|rowsnest|yberpatrol)|d(?:bot/|le_spider|om' .
        'ainappender|umprendertree)|flightdeckreportsbot|g(?:imme60|oogleben' .
        'jojo)|http-?(?:agent|client)|i(?:nternetcensus|ps-agent|sitwp)|k(?:' .
        '2spider|emvi)|l(?:exxebot|ivelapbot|wp)|m(?:acinroyprivacyauditors|' .
        'asscan|etaintelligence)|n(?:aver|et(?:craft|trapport)|icebot|mapscr' .
        'iptingengine|rsbot)|p(?:4bot|4load|acrawler|ageglimpse|arsijoo|egas' .
        'usmonitoring|hantomjs|hpcrawl|ingdom|rlog)|r(?:arelyused|obo(?:cop|' .
        'spider)|yze)|s(?:can\.lol|creener|itedomain|mut|nap(?:preview)?bot|' .
        'oapclient|ocial(?:ayer|searcher)|ogou|ohuagent|oso|pyglass|quider|t' .
        'reetbot|ynapse)|urlappendbot|w(?:asalive|atchmouse|eb(?:-monitoring' .
        '|bot|masteraid|money|thumbnail)|hatweb|ikiapiary|in(?:http|inet)|ma' .
        'id\.com|sr-agent|wwtype)|xenu|xovi|yeti|zibber|zurichfinancialservi' .
        'ces|^m$)~',
    $UANoSpace), 'Unauthorised'); // 2018.05.01

    $Trigger(preg_match(
        '/(?:^(bot|java|msie|windows-live-social-object-extractor)|\((java|\w\:\d{2,}))/',
    $UANoSpace), 'Unauthorised'); // 2018.06.24

    $Trigger(preg_match('~(?:\W|^)(?:cu|pe)rl(?:\W|$)~', $UANoSpace), 'Unauthorised'); // 2018.06.24

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

    $Trigger(preg_match('~(?:[./]seo|seo/)~', $UANoSpace), 'SEO UA'); // 2018.07.10

    $Trigger(strpos($UA, 'bittorrent') !== false, 'Bad context (not a bittorrent hub)'); // 2017.02.25

    $Trigger(empty($CIDRAM['Ignore']['Seznam.cz']) && strpos($UANoSpace, 'seznambot') !== false, 'Seznam.cz'); // 2017.02.02 (ASNs 43037, 200600)

}
