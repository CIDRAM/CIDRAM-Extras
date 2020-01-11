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
 * This file: Bad TLDs blocker module (last modified: 2020.01.11).
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

    $Trigger(preg_match(
        '~\.(?:bid|click|club?|country|cricket|date|diet|domain|download|fai' .
        'th|gdn|gq|kim|link|men|museum|party|racing|review|science|stream|to' .
        'kyo|top|webcam|website|win|work|xyz|yokohama|zip)$~i',
        $CIDRAM['Hostname']
    ), 'Disreputable TLD'); // 2018.04.08

    $Trigger(preg_match('~\.onion$~i', $CIDRAM['Hostname']), 'Anonymous/Unroutable TLD'); // 2017.12.28
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
