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
 * This file: Search engines blocker module (last modified: 2021.07.02).
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
    /** Guard. */
    if (empty($CIDRAM['BlockInfo']['IPAddr'])) {
        return;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Blocks requests from Baidu/百度. */
    if ($CIDRAM['Config']['seblocker']['block_baidu']) {
        /** Set flag to ignore validation. */
        $CIDRAM['Flag-Bypass-Baidu-Check'] = true;

        /** Fetch hostname. */
        if (empty($CIDRAM['Hostname'])) {
            $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
        }

        /** Block based on UA or hostname. */
        if ($Trigger(
            strpos(strtolower($CIDRAM['BlockInfo']['UA']), 'baidu') !== false,
            'Baidu/百度 UA',
            $CIDRAM['Config']['seblocker']['baidu_block_message']
        ) || $Trigger(
            preg_match('~(?:baidu|bdstatic|hao123)\.~i', $CIDRAM['Hostname']),
            'Baidu/百度 Host',
            $CIDRAM['Config']['seblocker']['baidu_block_message'])
        ) {
            $CIDRAM['AddProfileEntry']('Blocked search engine');
        }
    }

    /** Blocks requests from Sogou/搜狗. */
    if ($CIDRAM['Config']['seblocker']['block_sogou']) {
        /** Set flag to ignore validation. */
        $CIDRAM['Flag-Bypass-Sogou-Check'] = true;

        /** Fetch hostname. */
        if (empty($CIDRAM['Hostname'])) {
            $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
        }

        /** Block based on UA or hostname. */
        if ($Trigger(
            strpos(strtolower($CIDRAM['BlockInfo']['UA']), 'sogou') !== false,
            'Sogou/搜狗 UA',
            $CIDRAM['Config']['seblocker']['sogou_block_message']
        ) || $Trigger(
            preg_match('~sogou\.~i', $CIDRAM['Hostname']),
            'Sogou/搜狗 Host',
            $CIDRAM['Config']['seblocker']['sogou_block_message'])
        ) {
            $CIDRAM['AddProfileEntry']('Blocked search engine');
        }
    }

    /** Blocks requests from Yandex/Яндекс. */
    if ($CIDRAM['Config']['seblocker']['block_yandex']) {
        /** Set flag to ignore validation. */
        $CIDRAM['Flag-Bypass-Yandex-Check'] = true;

        /** Fetch hostname. */
        if (empty($CIDRAM['Hostname'])) {
            $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
        }

        /** Block based on UA or hostname. */
        if ($Trigger(
            strpos(strtolower($CIDRAM['BlockInfo']['UA']), 'yandex') !== false,
            'Yandex/Яндекс UA',
            $CIDRAM['Config']['seblocker']['yandex_block_message']
        ) || $Trigger(
            preg_match('~(?:yandex|yoomoney)\.~i', $CIDRAM['Hostname']),
            'Yandex/Яндекс Host',
            $CIDRAM['Config']['seblocker']['yandex_block_message'])
        ) {
            $CIDRAM['AddProfileEntry']('Blocked search engine');
        }
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
