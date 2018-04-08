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
 * This file: Bad TLDs blocker module (last modified: 2018.04.08).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Inherit bypass closure (see functions.php). */
$Bypass = $CIDRAM['Bypass'];

/** Fetch hostname. */
if (empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Signatures start here. */
if ($CIDRAM['Hostname'] && $CIDRAM['Hostname'] !== $CIDRAM['BlockInfo']['IPAddr']) {

    $Trigger(preg_match(
        '~\.(?:bid|click|club?|country|cricket|date|diet|domain|download|fai' .
        'th|gdn|gq|kim|link|men|museum|party|racing|review|science|stream|to' .
        'kyo|top|webcam|website|win|work|xyz|yokohama|zip)$~i',
        $CIDRAM['Hostname']
    ), 'Disreputable TLD'); // 2018.04.08

    $Trigger(preg_match('~\.onion$~i', $CIDRAM['Hostname']), 'Anonymous/Unroutable TLD'); // 2017.12.28

}
