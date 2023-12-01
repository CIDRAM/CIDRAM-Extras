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
 * This file: Referrer spam module (last modified: 2023.12.01).
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
 * Fetch Symfony polyfills for Idn (needed to process international domain
 * names, which utilise punycode, which requires Idn functionality to decode).
 */
if (!function_exists('idn_to_utf8') && is_readable($CIDRAM['Vault'] . 'classes/Symfony/bootstrap.php')) {
    require $CIDRAM['Vault'] . 'classes/Symfony/bootstrap.php';
}

/** Defining as closure for later recall (no params; no return value). */
$CIDRAM['ModuleResCache'][$Module] = function () use (&$CIDRAM) {
    /** Guard. */
    if (empty($CIDRAM['BlockInfo']['IPAddr'])) {
        return;
    }

    /** If the referrer isn't populated, exit early. */
    if ($CIDRAM['BlockInfo']['Referrer'] === '') {
        return;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Process to get the domain part. */
    $Domain = preg_replace(['~^[a-z]+:[\\/]*(?:www\d*\.)?~i', '~[\\/:].*$~', '[ \n\r]'], '', $CIDRAM['BlockInfo']['Referrer']);

    /** Lower-case domain part. */
    $RefLC = strtolower($Domain);

    /** Convert punycode to UTF-8. */
    if (strpos($RefLC, 'xn--') !== false) {
        $Domain = explode('.', $Domain);
        foreach ($Domain as &$DomainPart) {
            if (strtolower(substr($DomainPart, 0, 4)) !== 'xn--') {
                continue;
            }
            try {
                $DomainPartTest = idn_to_utf8($DomainPart);
                if ($DomainPartTest) {
                    $DomainPart = $DomainPartTest;
                }
            } catch (\Exception $e) {
            }
        }
        unset($DomainPartTest, $e, $DomainPart);
        $Domain = implode('.', $Domain);
    }

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
            'ch|speedup-my|v-casino|website-speed-check(?:er)?)\.site|(?:annaeydlish|' .
            'art(?:blog|press)|axcus|bitcoin-ua|blog(?:20\d\d|4u)|bpro1|compliance-[a' .
            '-z]{1,8}|gepatit-info|greatblog|josephineblog|kevblog|raymondblog|seo(?:' .
            '-tips|book)|space20\d\d|supermama|teresablog|wallinside|подушки)\.top|0n' .
            '-line\.tv|(?:\d-(?:easy|go-now)|a(?:bcde(?:fh|g)|ccount-my\d|dvokateg|lf' .
            'abot|nalytics-ads|nimalphotos|rendovalka)|b(?:est-seo-software|iteg|log2' .
            '0\d\d|logseo|oltalko|rateg|udilneg|uketeg|ukleteg)|compliance-[a-z]{1,8}' .
            '|(?:eu-)?cookie-law-enforcement-.{1,8}|eurocredit|dailyseo|ecblog|ekatal' .
            'og|eurocredit|flyblog|free-(?:social-buttons\d?|traffic)|ilovevitaly|jus' .
            'tprofit|law-(?:check-two|enforcement-(?:bot-ff|check-three|ee)|six)|lsex' .
            '|net-profits|one-a-plus|rusexy|share-buttons|slow-website|social(?:-?but' .
            'tons?-?.{0,2}|-traffic-\d+|-widget)|traffic(?:[-2]cash|genius)|web-reven' .
            'ue)\.xyz)$~i',
            $Domain
        ), 'Referrer spam detected (' . $Domain . ')') || // (info, site, top, tv, xyz) 2020.04.13
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
            $Domain
        ), 'Referrer spam detected (' . $Domain . ')') || // (Generic SEO/traffic refspam) 2019.09.28
        $Trigger(preg_match(
            '~(?:-blanca|-fulldrive|-zheleza|[a-z]{2,3}-lk-rt|allvacancy|artclipart|b' .
            'eclean-nn|dev-seo|dojki-devki|ege-essay|englishtopic|fialka\.tomsk|gelst' .
            'ate|gidonline|hit-kino|iskussnica|kabinet-[-a-z\d]{1,16}|lalalove|mamyli' .
            'k|mydoctorok|novosti-hi-tech|oklad|onlinewot|php-market|porn|pospektr|ps' .
            'n-card|rustag|serialsx|skinali\.photo-clip|sowhoz|sta-grand|stroi-24|su1' .
            'ufa|ximoda|your-tales)\.(?:blog|mobi|ru)$~i',
            $Domain
        ), 'Referrer spam detected (' . $Domain . ')') || // (blog, mobi, ru) 2019.09.28
        $Trigger(preg_match(
            '~(?:(?:-kredit|predmety|ukrtvory|пептиды|zagadki)\.in|-dereva\.kiev|auto' .
            'blog\.org|credit\.co|(?:kakadu-interior|naturalpharm|shopfishing|supermo' .
            'dni|vezdevoz)\.com)\.ua$|(?:ecommerce-seo|generalporn)\.org|-on-you\.ga|' .
            'blog(?:\d+\.org|star\.fun|total\.de)$|(?:-gratis|kakablog|xxx)\.net|porn' .
            '[-o]?(?:best|dl|forum|hd\d+|hive|hub-forum|semki|slave)\.(?:com|ga|info|' .
            'net|online|org|su|uni\.me)$|scat\.porn|sexyteens\.|topseoservices?\.co|(' .
            '?:эротический-массаж|чеки)\.москва$|[\x7f-\xff].*\.su$|собственники\.рус' .
            '|xtraffic\.|fetish\.(?:com|site)$|coast\.com$|library\.cc$~i',
            $Domain
        ), 'Referrer spam detected (' . $Domain . ')') || // (ua, su, porn refspam, etc) 2020.04.13
        $Trigger(preg_match(
            '~(?:(?:drev|mrbojikobi4|s-forum)\.biz|infogame\.name|(?:expediacustomers' .
            'ervicenumber|kinostar)\.online|(?:anabolics|veles)\.shop)$~i',
            $Domain
        ), 'Referrer spam detected (' . $Domain . ')') || // (biz, name, online, shop) 2019.09.28
        $Trigger(preg_match(
            '~(?:aitiman\.ae|rutor\.group|(?:medbrowse|piluli)\.info|(?:dantk|kazlent' .
            'a)\.kz|rxshop\.md|(?:belreferatov|mnogabukaff|sexuria|sssexxx|torrentgam' .
            'er)\.net|vseigru\.one|draniki\.org|vpdr\.pl)$~i',
            $Domain
        ), 'Referrer spam detected (' . $Domain . ')') || // (misc. other) 2019.09.28
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
            '|wordpress-start|x-lime|xtrafficplus|yes-do-now|youporn-ru|your-good-lin' .
            'ks|ретро-электро|лечениенаркомании|интересное\.ru)(?:24h)?\.com$~i',
            $Domain
        ), 'Referrer spam detected (' . $Domain . ')') // (misc. other + more porn refspam) 2020.04.13
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
        'nthroid|tentacle|viagra|xanax)~i',
        $Domain
    ), 'Referrer spam detected (' . $Domain . ')')) {
        $CIDRAM['Reporter']->report([10], [
            'Referrer spam originating from this address detected (' . $Domain . ').'
        ], $CIDRAM['BlockInfo']['IPAddr']);
    } // (Some of these are quite old and mightn't be relevant anymore) 2019.08.14

    if ($Trigger(preg_match(
        '~(?:android-style|anti-crisis-seo|hvd-store|med-dopomoga|oohlivecams|pai' .
        'nting-planet|vzubkah)\.com|quickchange\.cc|(?:sharebutton|spravkavspb)\.' .
        'net|elvel\.com\.ua|shoppingmiracles\.co\.uk|(?:biz-law|brothers-smaller|' .
        'enter-unicredit|gazel-72|moneyzzz|moyaskidka|poddon-moskva|tds-west|viel' .
        '|yur-p|адвокат-красногорск|болезни-глаз|годом|грузоподъемные-машины|жк-(' .
        '?:династия\.новостройки-ростова-\d+|западная-резиденция)|здоровье-природ' .
        'ы|интересное|каталог-скинали|купить-софосбувир|курсы-английского-языка-в' .
        '-самаре|лечениенаркомании|масло-кедра|мягкиеокнасаранск|непереводимая|от' .
        'четные-документы-спб|первый-жк|профмонтаж-врн|ретро-электросветогор-свет' .
        '|сказка-жк-ростов|снятьдомвсевастополе|холодныйобзвон|чек-г(?:арант|ости' .
        'ницы))\.(?:[rs]u|рф)~i',
        $Domain
    ), 'Referrer spam detected (' . $Domain . ')')) {
        $CIDRAM['Reporter']->report([10], [
            'Referrer spam originating from this address detected (' . $Domain . ').'
        ], $CIDRAM['BlockInfo']['IPAddr']);
    } // (circa ~2020 additions) 2020.04.13

    if ($Trigger(preg_match(
        '~anonymousfox\.co|binance\.com~i',
        $Domain
    ), 'Referrer spam detected (' . $Domain . ')')) {
        $CIDRAM['Reporter']->report([10, 15, 21], [
            'Referrer spam associated with WordPress/WooCommerce hack attempts detected (' . $Domain . ').'
        ], $CIDRAM['BlockInfo']['IPAddr']);
    } // 2023.06.16

    $Trigger($RefLC === '(null)', 'Illegal referrer'); // 2018.03.13
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
