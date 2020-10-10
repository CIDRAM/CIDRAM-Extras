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
 * This file: BunnyCDN compatibility module (last modified: 2020.09.12).
 *
 * False positive risk (an approximate, rough estimate only): « [x]Low [ ]Medium [ ]High »
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

    /** Converts the raw data from the BunnyCDN API to an array. */
    $IPList = (substr($CIDRAM['API']['BunnyCDN']['Data'], 0, 1) === '<') ? array_filter(
        explode('<>', preg_replace('~<[^<>]+>~', '<>', $CIDRAM['API']['BunnyCDN']['Data']))
    ) : (array_filter(
        explode(',', preg_replace('~["\'\[\]]~', '', $CIDRAM['API']['BunnyCDN']['Data']))
    ) ?: '');

    /** Execute configured action for positive matches against the BunnyCDN IP list. */
    if (is_array($IPList) && in_array($CIDRAM['BlockInfo']['IPAddr'], $IPList, true)) {

        /** Prevents search engine and social media verification. */
        $CIDRAM['SkipVerification'] = true;

        /** Bypass the request. */
        if ($CIDRAM['Config']['bunnycdn']['positive_action'] === 'bypass') {
            $CIDRAM['Bypass']($CIDRAM['BlockInfo']['SignatureCount'] > 0, 'BunnyCDN bypass');
            return;
        }

        /** Greylist the request. */
        if ($CIDRAM['Config']['bunnycdn']['positive_action'] === 'greylist') {
            $CIDRAM['ZeroOutBlockInfo']();
            return;
        }

        /** Whitelist the request. */
        if ($CIDRAM['Config']['bunnycdn']['positive_action'] === 'whitelist') {
            $CIDRAM['ZeroOutBlockInfo'](true);
            return;
        }
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
