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
 * This file: Referrer spam module (last modified: 2020.01.11).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Safety. */
if (!isset($CIDRAM['ModuleResCache'])) {
    $CIDRAM['ModuleResCache'] = [];
}

/** Defining as closure for later recall (no params; no return value). */
$CIDRAM['ModuleResCache'][$Module] = function () use (&$CIDRAM) {

    /** If the referrer isn't populated, exit early. */
    if ($CIDRAM['BlockInfo']['Referrer'] === '') {
        return;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Process to get the domain part. */
    $Domain = preg_replace(['~^[a-z]+\:[\\/]*(?:www\d*\.)?~i', '~[\\/\:].*$~'], '', $CIDRAM['BlockInfo']['Referrer']);

    /** Signatures begin here. */
    if (
        $Trigger(preg_match(
            '~(?:(?:\d{1,8}[a-z]{1,2}|a(?:dviceforum|llknow|llwomen|rtdeko|vkzaraboto' .
            'k)|b(?:estoffer[a-z]{1,8}|if-ru|izru|luerobot|rillianty|uy-cheap-online)' .
            '|call-of-duty|earnian-money|f(?:inansov|or-marketersy|orsex|orum69|reeno' .
            'de|reewlan)|get(?:-clickize|-more-free(?:er|ish)?-visitors|-your-social-' .
            'buttons|a?adsincome(?:ly)?|[fp]y-click|richquick(?:ly)?)|gobongo|gorgaz|' .
            'growth-?hacking(?:an|or|y)|ilovevitaly|increasewwwtraffic|inform-ua|kino' .
            '-key|krumble-?(?:adsde|adsen|ent-ads)|lerporn|medbrowse|money7777|nubuil' .
            'derian|online-hit|perform-like(?:-alibabaity|ism-alibaba)|piluli|porno(?' .
            ':-chaman|elita|semki)|ranksonic|savetubevideo|smartphonediscount|svetka|' .
            'wallpaperdesk|we-ping-for-youic|website-analyzer|worldmed|ww2awards|zdor' .
            'ovie-nogi)\.info|(?:24x7-server-support|2your|dosugrostov|jav-fetish|ker' .
            'ch|speedup-my|website-speed-check(?:er)?)\.site|(?:annaeydlish|art(?:blo' .
            'g|press)|axcus|bitcoin-ua|blog(?:20\d\d|4u)|bpro1|compliance-[a-z]{1,8}|' .
            'gepatit-info|greatblog|josephineblog|kevblog|raymondblog|seo(?:-tips|boo' .
            'k)|space20\d\d|supermama|teresablog|wallinside|xn--d1aifoe0a9a)\.top|0n-' .
            'line\.tv|xn--(?:---(?:--53dbcapga5atlplfdm6ag1ab1bvehl0b7toa0k|6kcamwewc' .
            'd9bayelq|7kcaaxchbbmgncr7chzy0k0hk|clckdac3bsfgdft3aebjp5etek)|--(?:7sba' .
            'bhjc3ccc5aggbzfmfi|7sbabn5abjehfwi8bj|7sbbpe3afguye|7sbho2agebbhlivy|8sb' .
            'aki4azawu5b|8sbhefaln6acifdaon5c6f4axh|8sblgmbj1a1bk8l\.xn----161-4vemb6' .
            'cjl7anbaea3afninj|btbdvdh4aafrfciljm6k|ctbbcjd3dbsehgi|ctbfcdjl8baejhfb1' .
            'oh|ctbigni3aj4h|ftbeoaiyg1ak1cb7d)|80aaajkrncdlqdh6ane8t|80adaggc5bdhlfa' .
            'msfdij4p7b|80adgcaax6acohn6r|90acenikpebbdd4f6d|c1acygb)\.xn--p1ai|(?:\d' .
            '-(?:easy|go-now)|a(?:bcde(?:fh|g)|ccount-my\d|dvokateg|lfabot|nalytics-a' .
            'ds|nimalphotos|rendovalka)|b(?:est-seo-software|iteg|log20\d\d|logseo|ol' .
            'talko|rateg|udilneg|uketeg|ukleteg)|compliance-[a-z]{1,8}|(?:eu-)?cookie' .
            '-law-enforcement-.{1,8}|eurocredit|dailyseo|ecblog|ekatalog|eurocredit|f' .
            'lyblog|free-(?:social-buttons\d?|traffic)|ilovevitaly|justprofit|law-(?:' .
            'check-two|enforcement-(?:bot-ff|check-three|ee)|six)|lsex|net-profits|on' .
            'e-a-plus|rusexy|share-buttons|slow-website|social(?:-?buttons?-?.{0,2}|-' .
            'traffic-\d+|-widget)|traffic(?:[-2]cash|genius)|web-revenue)\.xyz)$~i',
        $Domain), 'Referrer spam detected (' . $Domain . ')') || // (info, site, top, tv, xn--p1ai, xyz) 2019.09.28
        $Trigger(preg_match(
            '~(?:(?:(?:ai-?|auto|-)seo-(?:services?|traffic)|3(?:-letter-domains|wayn' .
            'etworks)?|\d-\d{0,4}(?:seo|best|free)(?:-?seo|-?best|-?free|-?share-butt' .
            'ons)|\d{0,4}(?:-reasons-for-seo|dollars-seo|searchengines)|\d{1,2}(?:\D' .
            '\D\d|-steps-to-start-business|forex|inn|istoshop|kop|make-?money-?online' .
            '|masterov|pamm|s?hopp?ing|webmasters?|zap)|buttons-for-(?:your-)?website' .
            '|e-commerce-seo\d|free-(?:(?:fb|fbook|floating|share|social|website)-(?:' .
            'buttons|traffic)|traffic-now|video-tool)|get-seo-help|o-o-\d{0,4}-o-o|se' .
            'o(?:analyses|checkup.?|experiment.?|jokes|pub|services\d{1,4})|seo-(?:2-' .
            '0|platform|services-(?:b2b|wordpress)|smm)|top\d{0,4}-(?:seo|online)-(?:' .
            'service|games)|traffic(?:2cash|2money|monetizer?))\.(?:com|kz|ml|net|org' .
            '|ru|ua)|(?:ai|auto|best)-?(?:deal-hdd|ping-service-usa|seo-?(?:offer|ser' .
            'vice|solution|tip)s?)\.(?:blue|com|pro|tk))$~i',
        $Domain), 'Referrer spam detected (' . $Domain . ')') || // (Generic SEO/traffic refspam) 2019.09.28
        $Trigger(preg_match(
            '~(?:-blanca|-fulldrive|-zheleza|[a-z]{2,3}-lk-rt|allvacancy|artclipart|b' .
            'eclean-nn|dev-seo|dojki-devki|ege-essay|englishtopic|fialka\.tomsk|gelst' .
            'ate|gidonline|hit-kino|iskussnica|kabinet-[-a-z\d]{1,16}|lalalove|mamyli' .
            'k|mydoctorok|novosti-hi-tech|oklad|onlinewot|php-market|porn|pospektr|ps' .
            'n-card|rustag|serialsx|skinali\.photo-clip|sowhoz|sta-grand|stroi-24|su1' .
            'ufa|ximoda|your-tales)\.(?:blog|mobi|ru)$~i',
        $Domain), 'Referrer spam detected (' . $Domain . ')') || // (blog, mobi, ru) 2019.09.28
        $Trigger(preg_match(
            '~(?:(?:-kredit|predmety|ukrtvory|xn--d1abj0abs9d|zagadki)\.in|-dereva\.k' .
            'iev|autoblog\.org|credit\.co|(?:kakadu-interior|naturalpharm|shopfishing' .
            '|supermodni|vezdevoz)\.com)\.ua$|(?:ecommerce-seo|generalporn)\.org|-on-' .
            'you\.ga|blog(?:\d+\.org|star\.fun|total\.de)$|(?:-gratis|kakablog|xxx)\.' .
            'net|porn[-o]?(?:best|dl|forum|hd\d+|hive|hub-forum|semki|slave)\.(?:com|' .
            'ga|info|net|online|org|su|uni\.me)$|scat\.porn|sexyteens\.|topseoservice' .
            's?\.co|xn--(?:--8sbarihbihxpxqgaf0g1e|e1agf4c)\.xn--80adxhks$|xn--.*\.su' .
            '$|xn--90acjmaltae3acm.xn--p1acf|xtraffic\.|jav-?(?:fetish\.(?:com|site)|' .
            'coast\.com|library\.cc)$~i',
        $Domain), 'Referrer spam detected (' . $Domain . ')') || // (ua, su, porn refspam, etc) 2019.09.28
        $Trigger(preg_match(
            '~(?:(?:drev|mrbojikobi4|s-forum)\.biz|infogame\.name|(?:expediacustomers' .
            'ervicenumber|kinostar)\.online|(?:anabolics|veles)\.shop)$~i',
        $Domain), 'Referrer spam detected (' . $Domain . ')') || // (biz, name, online, shop) 2019.09.28
        $Trigger(preg_match(
            '~(?:aitiman\.ae|rutor\.group|(?:medbrowse|piluli)\.info|(?:dantk|kazlent' .
            'a)\.kz|rxshop\.md|(?:belreferatov|mnogabukaff|sexuria|sssexxx|torrentgam' .
            'er)\.net|vseigru\.one|draniki\.org|vpdr\.pl)$~i',
        $Domain), 'Referrer spam detected (' . $Domain . ')') || // (misc. other) 2019.09.28
        $Trigger(preg_match(
            '~(?:-poesie?|(?:arabic|spain)-poetry|-v-krym|\d[a-z]{2}\d|24h|4-less|alb' .
            'uteroli|automobile-spec|avcoast|backlinks-fast-top|baixar-musicas-gratis' .
            '|beauty-lesson|bestfortraders|bin-brokers|break-the-chains|buttons?-for-' .
            'free|cattyhealth|cheap(?:pills|traffic)|coverage-my|doggyhealthy|doxysex' .
            'y|eropho|fast-top|fb(?:ook)?-groups?-here|fix-website-errors?|for-(?:mul' .
            'tiple-locations|placing-articles|your-business)|foxjuegos|from-articles|' .
            'inmoll|marinetraffic|migronis|monitoring-(?:your-)?success|moyparnik|nar' .
            'osty|natali-forex|okoshkah|pills-?(?:order)?-?online|porno?(?:hub-ru|for' .
            'adult|gig|nik|plen)|red-bracelets|rus-lit|sel-hoz|sexyali|share-buttons|' .
            'success-seo|tamada69|top10-online-games|trusted-backlinks|uginekologa|vi' .
            'deo--production|vzubah|w2mobile-za|wakeupseoconsultant|webmaster-traffic' .
            '|wordpress-start|xn--(?:--itbbudqejbfpg3l|80aanaardaperhcem4a6i|e1aaajzc' .
            'hnkg\.ru)|x-lime|xtrafficplus|yes-do-now|youporn-ru|your-good-links)(?:2' .
            '4h)?\.com$~i',
        $Domain), 'Referrer spam detected (' . $Domain . ')') // (misc. other + more porn refspam) 2019.09.28
    ) {
        $CIDRAM['Reporter']->report([10], [
            'Referrer spam originating from this address detected (' . $Domain . ').'
        ], $CIDRAM['BlockInfo']['IPAddr']);
    }

    if ($Trigger(
        preg_match('~delta-?search|vi-view\.com~i', $Domain),
        'Referrer spam detected (' . $Domain . ')'
    )) {
        $CIDRAM['Reporter']->report([10, 20], [
            'Referrer spam with recognised correlation to malware originating from this address detected (host might be compromised).'
        ], $CIDRAM['BlockInfo']['IPAddr']);
    } // 2019.08.12

    if ($Trigger(preg_match(
        '~(?:[-b-df-hj-np-tv-z\d\.]{5}\.xyz|\.(?:country|cricket|gq|kim|link|part' .
        'y|review|science|work|xxx|xzone|zip)|powernetshop\.at|3w1\.eu|(?:cat-tre' .
        'e-house|doctoryuval|justfree|netvibes|traf(?:ers|ficfaker)|webscutest)\.' .
        'com|pyce\.info|(?:bankinfodata|facialforum)\.net|icetv\.ru|dvd\d+\.com\.' .
        'ua)$|(?:%d8%b3%d9%83%d8%b3|-24h\.|adultfriendfinder|aimtrust|cash-blog|e' .
        'yeglassesonlineshop|filseclab|gayxzone|healingstartswithus|investblog|ma' .
        'ssagemiracle|mskhirakurves|myyogamassage|sobacos|typegetrich|web-ads|\.a' .
        'dult|\.box\.net|adult\.|avelox|bea?stiality|c[1i]al[1i]s|deltasone|drugs' .
        '(?:-|tore)|eroti[ck]|finddotcom|forex|gabapentin|geriforte|ginkg?o|henta' .
        'i|incest|kamagra|laxative|lesbian|levitra|lexap|liker\.profile|lipitor|l' .
        'olita|meet-women|melaleuca|menthol|neurontin|nolvadex|paxil|pdfgen|pharm' .
        'a\.|pillz|plavix|propecia|prosti|rogaine|screenshot|shemale|sterapred|sy' .
        'nthroid|tentacle|viagra|xanax)~i'
    , $Domain), 'Referrer spam detected (' . $Domain . ')')) {
        $CIDRAM['Reporter']->report([10], [
            'Referrer spam originating from this address detected (' . $Domain . ').'
        ], $CIDRAM['BlockInfo']['IPAddr']);
    } // (Some of these are quite old and mightn't be relevant anymore) 2019.08.14

    $RefLC = strtolower($CIDRAM['BlockInfo']['Referrer']);

    $Trigger($RefLC === '(null)', 'Illegal referrer'); // 2018.03.13
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
