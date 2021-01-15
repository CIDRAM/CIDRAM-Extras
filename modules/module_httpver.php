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
 * This file: HTTP version checker module (last modified: 2021.01.15).
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
    if (($Split = strpos($_SERVER['SERVER_PROTOCOL'], '/')) !== false) {
        $Protocol = strtoupper(preg_replace('~[^A-Za-z]~', '', substr($_SERVER['SERVER_PROTOCOL'], 0, $Split)));
        $Version = explode('.', preg_replace('~[^\d.]~', '', substr($_SERVER['SERVER_PROTOCOL'], $Split + 1)), 2);
        $Major = (int)$Version[0];
        $Minor = isset($Version[1]) ? (int)$Version[1] : 0;
    } else {
        $Protocol = strtoupper(preg_replace('~[^A-Za-z]~', '', $_SERVER['SERVER_PROTOCOL']));
        $Version = explode('.', preg_replace('~[^\d.]~', '', $_SERVER['SERVER_PROTOCOL']), 2);
        $Major = (int)$Version[0];
        $Minor = isset($Version[1]) ? (int)$Version[1] : 0;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    if ($Protocol === 'HTTP') {
        /** See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Evolution_of_HTTP */
        $Trigger((
            ($CIDRAM['Config']['httpver']['http/0.9'] && $Major === 0 && $Minor === 9) ||
            ($CIDRAM['Config']['httpver']['http/0.x'] && $Major === 0 && $Minor !== 9) ||
            ($CIDRAM['Config']['httpver']['http/1.0'] && $Major === 1 && $Minor === 0) ||
            ($CIDRAM['Config']['httpver']['http/1.1'] && $Major === 1 && $Minor === 1) ||
            ($CIDRAM['Config']['httpver']['http/1.2'] && $Major === 1 && $Minor === 2) ||
            ($CIDRAM['Config']['httpver']['http/1.3'] && $Major === 1 && $Minor === 3) ||
            ($CIDRAM['Config']['httpver']['http/1.x'] && $Major === 1 && $Minor !== 0 && $Minor !== 1 && $Minor !== 2 && $Minor !== 3) ||
            ($CIDRAM['Config']['httpver']['http/2.0'] && $Major === 2 && $Minor === 0) ||
            ($CIDRAM['Config']['httpver']['http/2.x'] && $Major === 2 && $Minor !== 0) ||
            ($CIDRAM['Config']['httpver']['http/3.0'] && $Major === 3 && $Minor === 0) ||
            ($CIDRAM['Config']['httpver']['http/3.x'] && $Major === 3 && $Minor !== 0) ||
            ($CIDRAM['Config']['httpver']['http/other'] && $Major !== 0 && $Major !== 1 && $Major !== 2 && $Major !== 3)
        ), 'Protocol denied', $CIDRAM['Config']['httpver']['reason_message']);
    } elseif ($Protocol === 'SHTTP') {
        $Trigger((
            ($CIDRAM['Config']['httpver']['shttp/1.3'] && $Major === 1 && $Minor === 3) ||
            ($CIDRAM['Config']['httpver']['shttp/other'] && !($Major === 1 && $Minor === 3))
        ), 'Protocol denied', $CIDRAM['Config']['httpver']['reason_message']);
    } elseif ($Protocol === 'IRC') {
        /** See: https://tools.ietf.org/html/rfc7230 */
        $Trigger((
            ($CIDRAM['Config']['httpver']['irc/6.9'] && $Major === 6 && $Minor === 9) ||
            ($CIDRAM['Config']['httpver']['irc/other'] && !($Major === 6 && $Minor === 9))
        ), 'Protocol denied', $CIDRAM['Config']['httpver']['reason_message']);
    } elseif ($Protocol === 'RTA') {
        $Trigger((
            ($CIDRAM['Config']['httpver']['rta/x11'] && $_SERVER['SERVER_PROTOCOL'] === 'RTA/x11') ||
            ($CIDRAM['Config']['httpver']['rta/other'] && $_SERVER['SERVER_PROTOCOL'] !== 'RTA/x11')
        ), 'Protocol denied', $CIDRAM['Config']['httpver']['reason_message']);
    } else {
        $Trigger($CIDRAM['Config']['httpver']['empty_unfamiliar'], 'Protocol denied', $CIDRAM['Config']['httpver']['reason_message']);
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
