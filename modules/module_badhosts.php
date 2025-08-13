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
 * This file: Bad hosts blocker module (last modified: 2025.08.11).
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
    /** Guard. */
    if (empty($CIDRAM['BlockInfo']['IPAddr'])) {
        return;
    }

    /** The number of signatures triggered by this point in time. */
    $Before = isset($CIDRAM['BlockInfo']['SignaturesCount']) ? $CIDRAM['BlockInfo']['SignaturesCount'] : 0;

    /** Don't continue if compatibility indicators exist. */
    if (strpos($CIDRAM['BlockInfo']['Signatures'], 'compat_bunnycdn.php') !== false) {
        return;
    }

    /** Fetch hostname. */
    if (empty($CIDRAM['Hostname'])) {
        $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
    }

    /** Safety mechanism against false positives caused by failed lookups. */
    if (
        !$CIDRAM['Hostname'] ||
        $CIDRAM['Hostname'] === $CIDRAM['BlockInfo']['IPAddr'] ||
        preg_match('~^b\.in-addr-servers\.nstld~', $CIDRAM['Hostname'])
    ) {
        return;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Inherit bypass closure (see functions.php). */
    $Bypass = $CIDRAM['Bypass'];

    /** Signatures start here. */
    $HN = preg_replace('/\s/', '', str_replace('\\', '/', strtolower(urldecode($CIDRAM['Hostname']))));
    $UA = str_replace('\\', '/', strtolower(urldecode($CIDRAM['BlockInfo']['UA'])));
    $UANoSpace = preg_replace('/\s/', '', $UA);

    $Trigger(preg_match('/\$(?:globals|_(?:cookie|env|files|get|post|request|server|session))/', $HN), 'Banned hostname'); // 2017.01.21 mod 2022.11.23

    $Trigger(preg_match('/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/', $HN), 'Hostname script injection'); // 2017.01.21

    $Trigger(preg_match('~captch|dbcapi\.me~', $HN), 'CAPTCHA cracker host'); // 2017.01.21

    $Trigger(preg_match(
        '~prking\.com\.au$|' .
        '(?:qvt|telsp)\.net\.br$|' .
        '(?:\.(?:giga-dns|oodle|pointandchange|solidseo(?:dedicated|vps)?|to' .
        'psy|vadino)|23gb|35up|accelovation|barefruit|bestprice|colo\.iinet|' .
        'detangled|kimsufi|lightspeedsystems|lipperhey|mantraonline|netcombe' .
        'r|myforexvps|page-store|setooz|stretchoid|technicolor)\.com$|' .
        'poneytelecom\.eu$|(?:4u|netadvert|onlinehome-server)\.info$|(?:3fn|' .
        'buyurl|dragonara|isnet|mfnx|onlinehome-server)\.net$|' .
        'seomoz\.org$|' .
        '(?:dimargroup|itrack|mail|rulinki|vipmailoffer)\.ru$|' .
        'b(?:oardreader|reakingtopics|uysellsales)|c(?:eptro|heapseovps|ybe' .
        'r-uslugi)|drugstore|liwio\.|luxuryhandbag|s(?:emalt|mileweb\.com\.' .
        'ua)|exabot~',
        $HN
    ), 'SEO/Bothost/Scraper/Spamhost'); // 2024.08.21 mod 2024.09.12

    $Trigger(preg_match('~cjh-law\.com$~', $HN), 'Phisher / Phishing Host'); // 2017.02.14

    $Trigger(preg_match('~exatt\.net$|unpef\.org$~', $HN), 'Pornobot/Pornhost'); // 2017.02.16

    $Trigger(preg_match(
        '~^(?:damage|moon|test)\.|anahaqq|core\.youtu\.me|fuc' . 'kyou|hoste' .
        'd-(?:by|in)|no-(?:data|(?:reverse-)?r?dns)|qeas|spletnahisa|therewi' .
        'll\.be|unassigned|work\.from|yhost\.name~',
        $HN
    ), 'Questionable Host'); // 2017.01.30 mod 2025.07.27

    $Trigger(preg_match('~anchorfree|hotspotsheild|esonicspider\.com$~', $HN), 'Hostile/esonicspider'); // 2018.09.15

    $Trigger(preg_match('~brandaffinity~', $HN), 'Hostile/SLAPP'); // 2018.09.15

    if (
        $Trigger(preg_match('~\.google(?:domains|usercontent)\.com$~', $HN), 'Google user content not permitted here') // 2022.06.22
    ) {
        $CIDRAM['AddProfileEntry']('Webhosting');
    }

    if ($Trigger(preg_match('/anonine\.com$|thefreevpn\.org$|vpn(?:999\.com|gate)/', $HN), 'Risky VPN Host')) {
        $CIDRAM['AddProfileEntry']('VPNs here');
    } // 2023.08.12

    $Trigger(preg_match('~shadowserver\.org$~', $HN), 'Regular unauthorised proxy tunnel attempts'); // 2023.09.15

    $Trigger(preg_match('~(?:iweb|privatedns)\.com$|iweb\.ca$|^(?:www\.)?iweb~', $HN), 'Domain Snipers'); // 2017.02.15 mod 2021.06.28

    $Trigger(preg_match('~amazonaws\.com$~', $HN) && (
        !preg_match('~alexa|postrank|twitt(?:urly|erfeed)|bitlybot|unwindfetchor|metauri|pinterest|slack|silk-accelerated=true$~', $UANoSpace) &&
        !preg_match('~(?:Feedspot http://www\.feedspot\.com|developers\.snap\.com/robots)$~', $CIDRAM['BlockInfo']['UA'])
    ), 'Amazon Web Services'); // 2023.02.28

    $Trigger(preg_match('/\.local$/', $HN), 'Spoofed/Fake Hostname'); // 2017.02.06

    /**
     * @link https://zb-block.net/zbf/showthread.php?t=25
     */
    $Trigger(preg_match('/shodan\.io|(?:serverprofi24|aspadmin|project25499)\./', $HN), 'AutoSploit Host'); // 2018.02.02 mod 2021.02.07

    $this->trigger(preg_match('~\.cypex\.ai$~', $HN), 'Unauthorised security scanner'); // 2025.08.11

    /** These signatures can set extended tracking options. */
    if (
        $Trigger(substr($HN, 0, 2) === '()', 'Banned hostname (Bash/Shellshock)') || // 2017.01.21
        $Trigger(preg_match(
            '/(?:0wn[3e]d|:(?:\{\w:|[\w\d][;:]\})|h[4a]ck(?:e[dr]|ing|[7t](?:[3e' .
            '][4a]m|[0o]{2}l))|%(?:0[0-8bcef]|1)|[`\'"]|^[-.:]|[-.:]$|[.:][\w\d-' .
            ']{64,}[.:])/i',
            $HN
        ), 'Banned hostname') || // 2018.06.24
        $Trigger((
            strpos($HN, 'rm ' . '-rf') !== false ||
            strpos($HN, 'sh' . 'el' . 'l_' . 'ex' . 'ec') !== false ||
            strpos($HN, '$_' . '[$' . '__') !== false ||
            strpos($HN, '@$' . '_[' . ']=' . '@!' . '+_') !== false
        ), 'Banned hostname') || // 2017.01.21
        $Trigger(preg_match('~rumer|pymep|румер~', $HN), 'Spamhost') || // 2017.01.21
        $Trigger(preg_match('/^localhost$/', $HN) && (
            !preg_match('/^(?:1(?:27|92\.168)(?:\.1?\d{1,2}|\.2[0-4]\d|\.25[0-5]){2,3}|::1)$/', $CIDRAM['BlockInfo']['IPAddr'])
        ), 'Spoofed/Fake Hostname') || // 2018.06.24
        $Trigger($HN === '.', 'DNS error') // 2017.02.25
    ) {
        $CIDRAM['Tracking options override'] = 'extended';
    }

    /**
     * Only to be triggered if other signatures haven't already been triggered
     * and if CIDRAM has been configured to block proxies.
     */
    if (
        !$CIDRAM['BlockInfo']['SignatureCount'] &&
        $CIDRAM['Config']['signatures']['block_proxies'] &&

        // Prevents matching against Facebook requests (updated 2020.02.07).
        !preg_match('~^fwdproxy-.*\.fbsv\.net$~i', $HN) &&

        /**
         * Prevents matching against (updated 2020.04.05):
         * - Google Translate
         * - Google Webmasters
         * - AdSense (Mediapartners)
         */
        !preg_match('~^(?:google|rate-limited)-proxy-.*\.google\.com$~i', $HN)
    ) {
        if ($Trigger(preg_match('~(?<!\w)tor(?!\w)|anonym|makesecure\.nl$|proxy~i', $HN), 'Proxy host')) {
            $CIDRAM['AddProfileEntry']('Tor endpoints here');
        } // 2021.03.18 mod 2022.07.07
    }

    /** WordPress cronjob bypass. */
    $Bypass(
        (($CIDRAM['BlockInfo']['SignatureCount'] - $Before) > 0) &&
        preg_match('~^/wp-cron\.php\?doing_wp_cron=\d+\.\d+$~', $CIDRAM['BlockInfo']['rURI']) &&
        defined('DOING_CRON'),
        'WordPress cronjob bypass'
    ); // 2018.06.24

    /** Conjunctive reporting. */
    if (preg_match('~Spoofed/Fake Hostname|Questionable Host|DNS error~i', $CIDRAM['BlockInfo']['WhyReason'])) {
        $CIDRAM['Reporter']->report([20], [], $CIDRAM['BlockInfo']['IPAddr']);
    }
    if (preg_match('~(?:VPN|Proxy) Host~i', $CIDRAM['BlockInfo']['WhyReason'])) {
        $CIDRAM['Reporter']->report([9, 13], [], $CIDRAM['BlockInfo']['IPAddr']);
    }

    /** Reporting. */
    if (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Banned hostname') !== false) {
        $CIDRAM['Reporter']->report([15], ['Hack attempt via hostname detected at this address.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Hostname script injection') !== false) {
        $CIDRAM['Reporter']->report([15], ['Script injection via hostname detected at this address.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'CAPTCHA cracker host') !== false) {
        $CIDRAM['Reporter']->report([15], ['CAPTCHA cracker detected at this address.'], $CIDRAM['BlockInfo']['IPAddr']);
    } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'esonicspider') !== false) {
        $CIDRAM['Reporter']->report([19, 21], ['esonicspider detected at this address.'], $CIDRAM['BlockInfo']['IPAddr']);
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
