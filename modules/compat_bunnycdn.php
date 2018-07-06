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
 * This file: BunnyCDN compatibility module (last modified: 2018.07.02).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Clear outdated API cache entries. */
$CIDRAM['ClearFromCache']('API');

/** Instantiate API cache. */
if (!isset($CIDRAM['Cache']['API'])) {
    $CIDRAM['Cache']['API'] = [];
}

/** Fetch BunnyCDN IP list. */
if (!isset($CIDRAM['Cache']['API']['BunnyCDN']['Data'])) {
    $CIDRAM['Cache']['API']['BunnyCDN'] = [
        'Data' => $CIDRAM['Request']('https://bunnycdn.com/api/system/edgeserverlist') ?: '',
        'Time' => $CIDRAM['Now'] + 345600
    ];
    $CIDRAM['CacheModified'] = true;
}

$IPList = (substr($CIDRAM['Cache']['API']['BunnyCDN']['Data'], 0, 1) === '<') ? array_filter(
    explode('<>', preg_replace('~<[^<>]+>~', '<>', $CIDRAM['Cache']['API']['BunnyCDN']['Data']))
) : (array_filter(
    explode(',', preg_replace('~["\'\[\]]~', '', $CIDRAM['Cache']['API']['BunnyCDN']['Data']))
) ?: '');

/** Inherit bypass closure (see functions.php). */
$Bypass = $CIDRAM['Bypass'];

/** Execute bypass for BunnyCDN IPs. */
if ($CIDRAM['BlockInfo']['SignatureCount'] > 0 && is_array($IPList)) {
    foreach ($IPList as $IP) {
        $Bypass($CIDRAM['BlockInfo']['IPAddr'] === $IP, 'BunnyCDN bypass');
    }
}
