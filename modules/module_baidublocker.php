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
 * This file: Baidu blocker module (last modified: 2017.01.16).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
$InstaBan = array('Options' => array('TrackTime' => 31536000, 'TrackCount' => 1000));

/** Set flag to ignore validation. */
$CIDRAM['Flag-Bypass-Baidu-Check'] = true;

/** Block based on UA. */
$Trigger(strpos(strtolower($CIDRAM['BlockInfo']['UA']), 'baidu') !== false, 'Baidu UA', '百度被禁止从这里', $InstaBan);

/** Fetch hostname. */
if (empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse-IPv4']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Block based on hostname. */
$Trigger(strpos(strtolower($CIDRAM['Hostname']), 'baidu') !== false, 'Baidu Host', '百度被禁止从这里', $InstaBan);

/*
IPv4 Signatures (ASNs 38365, 38627, 55967):

45.113.192.0/22 Deny 百度被禁止从这里
63.243.252.0/24 Deny 百度被禁止从这里
103.235.44.0/22 Deny 百度被禁止从这里
104.193.88.0/23 Deny 百度被禁止从这里
119.63.192.0/21 Deny 百度被禁止从这里
119.75.208.0/20 Deny 百度被禁止从这里
131.161.8.0/22 Deny 百度被禁止从这里
180.76.0.0/19 Deny 百度被禁止从这里
180.76.32.0/24 Deny 百度被禁止从这里
180.76.76.0/23 Deny 百度被禁止从这里
180.76.78.0/24 Deny 百度被禁止从这里
180.76.124.0/23 Deny 百度被禁止从这里
180.76.128.0/17 Deny 百度被禁止从这里
182.61.0.0/17 Deny 百度被禁止从这里
182.61.132.0/24 Deny 百度被禁止从这里
182.61.248.0/23 Deny 百度被禁止从这里
202.46.48.0/21 Deny 百度被禁止从这里
202.46.56.0/23 Deny 百度被禁止从这里
202.46.58.0/24 Deny 百度被禁止从这里
202.46.60.0/23 Deny 百度被禁止从这里
202.46.62.0/24 Deny 百度被禁止从这里
Tag: Baidu IPv4
---
Options:
 TrackTime: 31536000
 TrackCount: 1000

---
IPv6 Signatures (ASN 45076):

2400:da00::/32 Deny 百度被禁止从这里
Tag: Baidu IPv6
---
Options:
 TrackTime: 31536000
 TrackCount: 1000

*/
