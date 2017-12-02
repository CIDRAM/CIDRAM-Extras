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
 * This file: Yandex blocker module (last modified: 2017.12.03).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
$InstaBan = ['Options' => ['TrackTime' => 31536000, 'TrackCount' => 1000]];

/** Set flag to ignore validation. */
$CIDRAM['Flag-Bypass-Yandex-Check'] = true;

/** Block based on UA. */
$Trigger(strpos(strtolower($CIDRAM['BlockInfo']['UA']), 'yandex') !== false, 'Yandex UA', 'Яндекс запретили здесь', $InstaBan);

/** Fetch hostname. */
if (empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Block based on hostname. */
$Trigger(strpos(strtolower($CIDRAM['Hostname']), 'yandex') !== false, 'Yandex Host', 'Яндекс запретили здесь', $InstaBan);

/*
IPv4 Signatures (ASNs 13238, 43247, 202611, 207207):

5.45.192.0/18 Deny Яндекс запретили здесь
5.255.192.0/18 Deny Яндекс запретили здесь
37.9.64.0/18 Deny Яндекс запретили здесь
37.140.128.0/18 Deny Яндекс запретили здесь
77.75.152.0/21 Deny Яндекс запретили здесь
77.88.0.0/18 Deny Яндекс запретили здесь
84.201.128.0/18 Deny Яндекс запретили здесь
87.250.224.0/19 Deny Яндекс запретили здесь
93.158.128.0/18 Deny Яндекс запретили здесь
95.108.128.0/17 Deny Яндекс запретили здесь
100.43.64.0/19 Deny Яндекс запретили здесь
109.235.160.0/21 Deny Яндекс запретили здесь
141.8.128.0/18 Deny Яндекс запретили здесь
178.154.128.0/17 Deny Яндекс запретили здесь
185.32.185.0/24 Deny Яндекс запретили здесь
185.32.186.0/24 Deny Яндекс запретили здесь
185.71.76.0/22 Deny Яндекс запретили здесь
199.36.240.0/22 Deny Яндекс запретили здесь
213.180.192.0/19 Deny Яндекс запретили здесь
Tag: Yandex CIDRs
---
Options:
 TrackTime: 31536000
 TrackCount: 1000

---
IPv6 Signatures (ASNs 13238, 43247, 207207):

2001:678:384::/48 Deny Яндекс запретили здесь
2620:10f:d000::/44 Deny Яндекс запретили здесь
2a02:6b8::/32 Deny Яндекс запретили здесь
2a02:5180::/32 Deny Яндекс запретили здесь
Tag: Yandex CIDRs
---
Options:
 TrackTime: 31536000
 TrackCount: 1000

*/
