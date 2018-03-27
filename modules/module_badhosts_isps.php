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
 * This file: Bad hosts blocker module (last modified: 2018.03.27).
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
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Signatures start here. */
if ($CIDRAM['Hostname'] && $CIDRAM['Hostname'] !== $CIDRAM['BlockInfo']['IPAddr']) {
    $HN = preg_replace('/\s/', '', str_replace("\\", '/', strtolower(urldecode($CIDRAM['Hostname']))));

    $Trigger(preg_match(
        '/(?:\.telecom\.net\.ar$|brasiltelecom\.net\.br$|hgc\.com\.hk$|\.duo' .
        '\.carnet\.hr$|\.pool-xxx\.hcm\.fpt$|kiyosho\.jp$|(?:hinet|vtr)\.net' .
        '$|vip-net\.pl$)/',
    $HN), 'Spammy ISP', '', $reCAPTCHA); // 2018.03.27

    $Trigger(empty($CIDRAM['Ignore']['Sun Network HK']) && preg_match('/sunnetwork\.com\.hk$/', $HN), 'Spammy ISP'); // 2018.03.27 (ASN 38197)
}

/** WordPress cronjob bypass. */
$Bypass(
    (($CIDRAM['BlockInfo']['SignatureCount'] - $Infractions) > 0) &&
    preg_match('~^/wp-cron\.php\?doing_wp_cron=[0-9]+\.[0-9]+$~', $_SERVER['REQUEST_URI']) &&
    defined('DOING_CRON'),
'WordPress cronjob bypass');
