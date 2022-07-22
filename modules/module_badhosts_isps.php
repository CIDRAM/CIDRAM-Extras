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
 * This file: Bad hosts blocker module (last modified: 2022.07.22).
 *
 * False positive risk (an approximate, rough estimate only): « [ ]Low [ ]Medium [x]High »
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM') && !defined('CIDRAM-L')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Safety. */
if (!isset($CIDRAM['ModuleResCache'])) {
    $CIDRAM['ModuleResCache'] = [];
}

/** Defining as closure for later recall (no params; no return value). */
$CIDRAM['ModuleResCache'][$Module] = function () use (&$CIDRAM) {
    /** Guard. */
    if (empty($CIDRAM['BlockInfo']['IPAddr'])) {
        return;
    }

    /** The number of signatures triggered by this point in time. */
    $Before = isset($CIDRAM['BlockInfo']['SignaturesCount']) ? $CIDRAM['BlockInfo']['SignaturesCount'] : 0;

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

    /** Inherit bypass closure (see functions.php). */
    $Bypass = $CIDRAM['Bypass'];

    /** Marks for use with reCAPTCHA and hCAPTCHA. */
    $EnableCaptcha = ['recaptcha' => ['enabled' => true], 'hcaptcha' => ['enabled' => true]];

    $HN = preg_replace('/\s/', '', str_replace("\\", '/', strtolower(urldecode($CIDRAM['Hostname']))));

    $Trigger(preg_match(
        '/(?:hgc\.com\.hk$|\.duo\.carnet\.hr$|\.pool-xxx\.hcm\.fpt$|kiyosho\.jp$|(?:hinet|vtr)\.net$|vip-net\.pl$)/',
        $HN
    ), 'Spammy ISP', '', $EnableCaptcha); // 2020.04.05

    /** WordPress cronjob bypass. */
    $Bypass(
        (($CIDRAM['BlockInfo']['SignatureCount'] - $Before) > 0) &&
        preg_match('~^/wp-cron\.php\?doing_wp_cron=\d+\.\d+$~', $CIDRAM['BlockInfo']['rURI']) &&
        defined('DOING_CRON'),
        'WordPress cronjob bypass'
    ); // 2018.06.24
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
