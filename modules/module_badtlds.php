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
 * This file: Bad TLDs blocker module (last modified: 2019.12.03).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Don't continue if compatibility indicators exist. */
$DoNotContinue = (
    strpos($CIDRAM['BlockInfo']['Signatures'], 'compat_bunnycdn.php') !== false
);

/** Fetch hostname. */
if (!$DoNotContinue && empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Safety mechanism against false positives caused by failed lookups. */
if (!$DoNotContinue && (!$CIDRAM['Hostname'] || preg_match('~^b\.in-addr-servers\.nstld~', $CIDRAM['Hostname']))) {
    $DoNotContinue = true;
}

/** Signatures start here. */
if (!$DoNotContinue && $CIDRAM['Hostname'] !== $CIDRAM['BlockInfo']['IPAddr']) {

    $Trigger(preg_match(
        '~\.(?:bid|click|club?|country|cricket|date|diet|domain|download|fai' .
        'th|gdn|gq|kim|link|men|museum|party|racing|review|science|stream|to' .
        'kyo|top|webcam|website|win|work|xyz|yokohama|zip)$~i',
        $CIDRAM['Hostname']
    ), 'Disreputable TLD'); // 2018.04.08

    $Trigger(preg_match('~\.onion$~i', $CIDRAM['Hostname']), 'Anonymous/Unroutable TLD'); // 2017.12.28

}
