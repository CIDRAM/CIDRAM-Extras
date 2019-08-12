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
 * This file: Referrer spam module (last modified: 2019.08.12).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/**
 * Referrer-based signatures start from here.
 * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
 */
if ($CIDRAM['BlockInfo']['Referrer']) {

    if (
        $Trigger(preg_match('~trafers\.com~i', $CIDRAM['BlockInfo']['Referrer']), 'Trafers not permitted here') || // 2017.12.07
        $Trigger(preg_match(
            '~(?:\d{1,8}[a-z]{1,2}|a(?:dviceforum|llknow|llwomen|rtdeko|vkzarabotok)|' .
            'b(?:estoffer[a-z]{1,8}|if-ru|izru|luerobot|rillianty|uy-cheap-online)|ca' .
            'll-of-duty|earnian-money|f(?:inansov|or-marketersy|orsex|orum69|reenode|' .
            'reewlan)|get(?:-clickize|-more-free(?:er|ish)?-visitors|-your-social-but' .
            'tons|a?adsincome(?:ly)?|[fp]y-click|richquick(?:ly)?)|gobongo|gorgaz|gro' .
            'wth-?hacking(?:an|or|y)|ilovevitaly|increasewwwtraffic|inform-ua|kino-ke' .
            'y|krumble-?(?:adsde|adsen|ent-ads)|lerporn|medbrowse|money7777|nubuilder' .
            'ian|online-hit|perform-like(?:-alibabaity|ism-alibaba)|piluli|porno(?:-c' .
            'haman|elita|semki)|ranksonic|savetubevideo|smartphonediscount|svetka|wal' .
            'lpaperdesk|we-ping-for-youic|website-analyzer|worldmed|ww2awards|zdorovi' .
            'e-nogi)\.info|(?:24x7-server-support|2your|dosugrostov|jav-fetish|kerch|' .
            'speedup-my|website-speed-check(?:er)?)\.site|(?:annaeydlish|art(?:blog|p' .
            'ress)|axcus|bitcoin-ua|blog(?:20\d\d|4u)|bpro1|compliance-[a-z]{1,8}|gep' .
            'atit-info|greatblog|josephineblog|kevblog|raymondblog|seo(?:-tips|book)|' .
            'space20\d\d|supermama|teresablog|wallinside|xn--d1aifoe0a9a)\.top|0n-lin' .
            'e\.tv|xn--(?:---(?:--53dbcapga5atlplfdm6ag1ab1bvehl0b7toa0k|6kcamwewcd9b' .
            'ayelq|7kcaaxchbbmgncr7chzy0k0hk|clckdac3bsfgdft3aebjp5etek)|--(?:7sbabhj' .
            'c3ccc5aggbzfmfi|7sbabn5abjehfwi8bj|7sbbpe3afguye|7sbho2agebbhlivy|8sbaki' .
            '4azawu5b|8sbhefaln6acifdaon5c6f4axh|8sblgmbj1a1bk8l\.xn----161-4vemb6cjl' .
            '7anbaea3afninj|btbdvdh4aafrfciljm6k|ctbbcjd3dbsehgi|ctbfcdjl8baejhfb1oh|' .
            'ctbigni3aj4h|ftbeoaiyg1ak1cb7d)|80aaajkrncdlqdh6ane8t|80adaggc5bdhlfamsf' .
            'dij4p7b|80adgcaax6acohn6r|90acenikpebbdd4f6d|c1acygb)\.xn--p1ai|(?:\d-(?' .
            ':easy|go-now)|a(?:bcde(?:fh|g)|ccount-my\d|dvokateg|lfabot|nalytics-ads|' .
            'nimalphotos|rendovalka)|b(?:est-seo-software|iteg|log20\d\d|logseo|oltal' .
            'ko|rateg|udilneg|uketeg|ukleteg)|compliance-[a-z]{1,8}|(?:eu-)?cookie-la' .
            'w-enforcement-.{1,8}|dailyseo|ecblog|ekatalog|eurocredit|flyblog|free-(?' .
            ':social-buttons\d?|traffic)|ilovevitaly|justprofit|law-(?:check-two|enfo' .
            'rcement-(?:bot-ff|check-three|ee)|six)|lsex|net-profits|one-a-plus|rusex' .
            'y|share-buttons|slow-website|social(?:-?buttons?-?.{0,2}|-traffic-\d+|-w' .
            'idget)|traffic(?:[-2]cash|genius)|web-revenue)\.xyz~i',
        $CIDRAM['BlockInfo']['Referrer']), 'Referrer spam detected') || // (info, site, top, tv, xn--p1ai, xyz) 2019.08.12
        $Trigger(preg_match(
            '~(?:(?:auto|-)seo-(?:services?|traffic)|3(?:-letter-domains|waynetworks)' .
            '?|\d-\d{0,4}(?:seo|best|free)(?:-?seo|-?best|-?free|-?share-buttons)|\d{' .
            '0,4}(?:-reasons-for-seo|dollars-seo|searchengines)|\d{1,2}(?:\D\D\d|-ste' .
            'ps-to-start-business|forex|inn|istoshop|kop|make-?money-?online|masterov' .
            '|pamm|s?hopp?ing|webmasters?|zap)|buttons-for-(?:your-)?website|e-commer' .
            'ce-seo\d|free-(?:(?:fb|fbook|floating|share|social|website)-(?:buttons|t' .
            'raffic)|traffic-now|video-tool)|get-seo-help|o-o-\d{0,4}-o-o|seo(?:analy' .
            'ses|checkup.?|experiment.?|jokes|pub|services\d{1,4})|seo-(?:2-0|platfor' .
            'm|services-(?:b2b|wordpress)|smm)|top\d{0,4}-(?:seo|online)-(?:service|g' .
            'ames)|traffic(?:2cash|2money|monetizer?))\.(?:com|kz|ml|net|org|ru|ua)|(' .
            '?:auto|best)-?(?:deal-hdd|ping-service-usa|seo-?(?:offer|solution|tips))' .
            '\.(?:blue|com|pro)~i',
        $CIDRAM['BlockInfo']['Referrer']), 'Referrer spam detected') || // (Generic SEO/traffic refspam) 2019.08.12
        $Trigger(preg_match(
            '~(?:-blanca|-fulldrive|-zheleza|[a-z]{2,3}-lk-rt|dev-seo|kabinet-[-a-z\d' .
            ']{1,16}|novosti-hi-tech|oklad|porn|ximoda)\.(?:blog|mobi|ru)~i',
        $CIDRAM['BlockInfo']['Referrer']), 'Referrer spam detected') || // (blog, mobi, ru) 2019.08.12
        $Trigger(preg_match(
            '~(?:(?:-kredit|xn--d1abj0abs9d)\.in|autoblog\.org|-dereva\.kiev)\.ua|(?:' .
            'ecommerce-seo|generalporn)\.org|-on-you\.ga|blog(?:\d+\.org|star\.fun|to' .
            'tal\.de)|(?:-gratis|kakablog|xxx)\.net|porn[-o]?(?:best|dl|forum|hd\d+|h' .
            'ive|hub-forum|slave)\.(?:com|ga|net|online|org|su|uni\.me)|scat\.porn|se' .
            'xyteens\.|topseoservices?\.co|xn--(?:--8sbarihbihxpxqgaf0g1e|e1agf4c)\.x' .
            'n--80adxhks|xn--.*\.su|xn--90acjmaltae3acm.xn--p1acf|xtraffic\.~i',
        $CIDRAM['BlockInfo']['Referrer']), 'Referrer spam detected') || // (ua, su, porn refspam, etc) 2019.08.12
        $Trigger(preg_match(
            '~(?:-v-krym|4-less|baixar-musicas-gratis|break-the-chains|buttons?-for-f' .
            'ree|cheaptraffic|doxysexy|fast-top|fb(?:ook)?-groups?-here|fix-website-e' .
            'rrors?|for-(?:multiple-locations|placing-articles|your-business)|from-ar' .
            'ticles|marinetraffic|monitoring-(?:your-)?success|pills-order-online|por' .
            'no?(?:hub-ru|foradult|gig|nik|plen)|red-bracelets|sexyali|share-buttons|' .
            'success-seo|trusted-backlinks|video--production|wakeupseoconsultant|webm' .
            'aster-traffic|wordpress-start|xn--(?:--itbbudqejbfpg3l|80aanaardaperhcem' .
            '4a6i|e1aaajzchnkg\.ru)|xtrafficplus|yes-do-now|youporn-ru)\.com~i',
        $CIDRAM['BlockInfo']['Referrer']), 'Referrer spam detected') // (misc. other + more porn refspam) 2019.08.12
    ) {
        $CIDRAM['Reporter']->report([10], ['Referrer spam originating from this address detected.'], $CIDRAM['BlockInfo']['IPAddr']);
    }

    if ($Trigger(
        preg_match('~delta-?search|vi-view\.com~i', $CIDRAM['BlockInfo']['Referrer']),
        'Referrer spam detected'
    )) {
        $CIDRAM['Reporter']->report(
            [10, 20],
            ['Referrer spam with recognised correlation to malware originating from this address detected (host might be compromised).'],
            $CIDRAM['BlockInfo']['IPAddr']
        );
    } // 2019.08.12

    if ($Trigger(preg_match(
        '~[-b-df-hj-np-tv-z\d\.]{5}\.xyz|\.(?:country|cricket|gq|kim|link|party|r' .
        'eview|science|work|xxx|xzone|zip)|powernetshop\.at|3w1\.eu|(?:cat-tree-h' .
        'ouse|doctoryuval|justfree|netvibes|trafficfaker|webscutest)\.com|pyce\.i' .
        'nfo|(?:bankinfodata|facialforum)\.net|icetv\.ru|dvd\d+\.com\.ua|(?:%d8%b' .
        '3%d9%83%d8%b3|-24h\.|adultfriendfinder|aimtrust|cash-blog|eyeglassesonli' .
        'neshop|filseclab|gayxzone|healingstartswithus||investblog|massagemiracle' .
        '|mskhirakurves|myyogamassage|sobacos|typegetrich|web-ads|\.adult|\.box\.' .
        'net|adult\.|avelox|bea?stiality|bestiality|c[1i]al[1i]s|deltasone|drugs(' .
        '?:-|tore)|eroti[ck]|finddotcom|forex|gabapentin|geriforte|ginkg?o|hentai' .
        '|incest|kamagra|laxative|lesbian|levitra|lexap|liker\.profile|lipitor|lo' .
        'lita|meet-women|melaleuca|menthol|neurontin|nolvadex|paxil|pdfgen|pharma' .
        '\.|pillz|plavix|propecia|prosti|rogaine|screenshot|shemale|sterapred|syn' .
        'throid|tentacle|viagra|xanax)~i'
    , $CIDRAM['BlockInfo']['Referrer']), 'Referrer spam detected')) {
        $CIDRAM['Reporter']->report([10], ['Referrer spam originating from this address detected.'], $CIDRAM['BlockInfo']['IPAddr']);
    } // (Some of these are quite old and mightn't be relevant anymore) 2019.08.12

    $RefLC = strtolower($CIDRAM['BlockInfo']['Referrer']);

    $Trigger($RefLC === '(null)', 'Illegal referrer'); // 2018.03.13

}
