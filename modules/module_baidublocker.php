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
 * This file: Baidu blocker module (last modified: 2020.08.08).
 *
 * False positive risk (an approximate, rough estimate only): « [x]Low [ ]Medium [ ]High »
 *
 * Warning: Will destroy your website's Baidu page rank!
 * Websites targeting Chinese speaking users should avoid this module.
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

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
    $InstaBan = ['Options' => ['TrackTime' => 31536000, 'TrackCount' => 1000]];

    /** Set flag to ignore validation. */
    $CIDRAM['Flag-Bypass-Baidu-Check'] = true;

    /** Block based on UA. */
    $Trigger(strpos(strtolower($CIDRAM['BlockInfo']['UA']), 'baidu') !== false, 'Baidu UA', '百度被禁止从这里', $InstaBan);

    /** Fetch hostname. */
    if (empty($CIDRAM['Hostname'])) {
        $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
    }

    /** Block based on hostname. */
    $Trigger(strpos(strtolower($CIDRAM['Hostname']), 'baidu') !== false, 'Baidu Host', '百度被禁止从这里', $InstaBan);
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();

/*
ASNs 38365, 38627, 55967

---
IPv4 Signatures

106.12.0.0/17 Deny 百度被禁止从这里
106.12.128.0/18 Deny 百度被禁止从这里
106.12.192.0/19 Deny 百度被禁止从这里
106.12.224.0/20 Deny 百度被禁止从这里
106.12.240.0/21 Deny 百度被禁止从这里
106.13.0.0/17 Deny 百度被禁止从这里
106.13.128.0/18 Deny 百度被禁止从这里
106.13.192.0/19 Deny 百度被禁止从这里
106.13.224.0/20 Deny 百度被禁止从这里
106.13.240.0/22 Deny 百度被禁止从这里
119.75.208.0/20 Deny 百度被禁止从这里
150.242.120.0/24 Deny 百度被禁止从这里
150.242.122.0/23 Deny 百度被禁止从这里
180.76.0.0/17 Deny 百度被禁止从这里
180.76.128.0/18 Deny 百度被禁止从这里
180.76.192.0/22 Deny 百度被禁止从这里
180.76.196.0/23 Deny 百度被禁止从这里
180.76.200.0/21 Deny 百度被禁止从这里
180.76.208.0/20 Deny 百度被禁止从这里
180.76.224.0/19 Deny 百度被禁止从这里
182.61.0.0/17 Deny 百度被禁止从这里
182.61.130.0/23 Deny 百度被禁止从这里
182.61.132.0/22 Deny 百度被禁止从这里
182.61.136.0/21 Deny 百度被禁止从这里
182.61.144.0/20 Deny 百度被禁止从这里
182.61.160.0/19 Deny 百度被禁止从这里
182.61.200.0/21 Deny 百度被禁止从这里
182.61.216.0/21 Deny 百度被禁止从这里
182.61.224.0/19 Deny 百度被禁止从这里
202.46.48.0/20 Deny 百度被禁止从这里
Origin: CN
185.10.104.0/24 Deny 百度被禁止从这里
Origin: EU
45.113.192.0/22 Deny 百度被禁止从这里
103.235.44.0/22 Deny 百度被禁止从这里
Origin: HK
119.63.192.0/21 Deny 百度被禁止从这里
Origin: JP
154.85.32.0/21 Deny 百度被禁止从这里
154.85.46.0/23 Deny 百度被禁止从这里
154.85.48.0/20 Deny 百度被禁止从这里
Origin: SC
63.243.252.0/24 Deny 百度被禁止从这里
104.193.88.0/23 Deny 百度被禁止从这里
104.193.90.0/24 Deny 百度被禁止从这里
Origin: US
Tag: Baidu IPv4
---
Options:
 TrackTime: 31536000
 TrackCount: 1000

---
IPv6 Signatures

2400:da00::/32 Deny 百度被禁止从这里
240c:4000::/22 Deny 百度被禁止从这里
Origin: CN
2402:2b40:8000::/36 Deny 百度被禁止从这里
2402:2b40:a000::/36 Deny 百度被禁止从这里
Origin: HK
Tag: Baidu IPv6
---
Options:
 TrackTime: 31536000
 TrackCount: 1000

*/
