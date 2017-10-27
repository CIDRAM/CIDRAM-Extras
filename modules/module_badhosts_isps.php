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
 * This file: Bad hosts blocker module (last modified: 2017.10.27).
 *
 * Many thanks to Michael Hopkins, the creator of ZB Block (GNU/GPLv2), and to
 * the community behind it (Spambot Security) for inspiring/developing many of
 * the signatures contained within this module.
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Inherit bypass closure (see functions.php). */
$Bypass = $CIDRAM['Bypass'];

/** Enables reCAPTCHA option for ISPs. */
$reCAPTCHA = ['recaptcha' => ['enabled' => true]];

/** Fetch hostname. */
if (empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse-IPv4']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Signatures start here. */
if ($CIDRAM['Hostname'] && $CIDRAM['Hostname'] !== $CIDRAM['BlockInfo']['IPAddr']) {
    $HN = preg_replace('/\s/', '', str_replace("\\", '/', strtolower(urldecode($CIDRAM['Hostname']))));

    $Trigger(preg_match(
        '/(?:\.telecom\.net\.ar$|brasiltelecom\.net\.br$|(hgc|sunnetwork)\.c' .
        'om\.hk$|\.duo\.carnet\.hr$|\.pool-xxx\.hcm\.fpt$|(\.cnr|retail\.tel' .
        'ecomitalia|tiscali)\.it$|kiyosho\.jp$|(hinet|vtr)\.net$|vip-net\.pl' .
        '$)/',
    $HN), 'Spammy ISP', '', $reCAPTCHA); // 2017.02.16

}

/** WordPress cronjob bypass. */
$Bypass(
    (($CIDRAM['BlockInfo']['SignatureCount'] - $Infractions) > 0) &&
    preg_match('~^/wp-cron\.php\?doing_wp_cron=[0-9]+\.[0-9]+$~', $_SERVER['REQUEST_URI']) &&
    defined('DOING_CRON'),
'WordPress cronjob bypass');
