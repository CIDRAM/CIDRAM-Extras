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
 * This file: BunnyCDN compatibility module (last modified: 2019.07.10).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Instantiate API cache. */
$CIDRAM['InitialiseCacheSection']('API');

/** Fetch BunnyCDN IP list. */
if (!isset($CIDRAM['API']['BunnyCDN'], $CIDRAM['API']['BunnyCDN']['Data'])) {
    $CIDRAM['API']['BunnyCDN'] = [
        'Data' => $CIDRAM['Request']('https://bunnycdn.com/api/system/edgeserverlist') ?: '',
        'Time' => $CIDRAM['Now'] + 345600
    ];
    $CIDRAM['API-Modified'] = true;
}

$IPList = (substr($CIDRAM['API']['BunnyCDN']['Data'], 0, 1) === '<') ? array_filter(
    explode('<>', preg_replace('~<[^<>]+>~', '<>', $CIDRAM['API']['BunnyCDN']['Data']))
) : (array_filter(
    explode(',', preg_replace('~["\'\[\]]~', '', $CIDRAM['API']['BunnyCDN']['Data']))
) ?: '');

/** Inherit bypass closure (see functions.php). */
$Bypass = $CIDRAM['Bypass'];

/** Execute bypass for BunnyCDN IPs. */
if (is_array($IPList) && in_array($CIDRAM['BlockInfo']['IPAddr'], $IPList, true)) {
    $CIDRAM['SkipVerification'] = true;
    $Bypass($CIDRAM['BlockInfo']['SignatureCount'] > 0, 'BunnyCDN bypass');
}
