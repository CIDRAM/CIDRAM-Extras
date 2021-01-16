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
 * This file: HTTP version checker module (last modified: 2021.01.16).
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
    } else {
        $Protocol = strtoupper(preg_replace('~[^A-Za-z]~', '', $_SERVER['SERVER_PROTOCOL']));
        $Version = explode('.', preg_replace('~[^\d.]~', '', $_SERVER['SERVER_PROTOCOL']), 2);
    }
    $Major = (int)$Version[0];
    $Minor = isset($Version[1]) ? (int)$Version[1] : 0;
    $Rebuilt = $Protocol . '/' . $Major . '.' . $Minor;

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    if ($Protocol === 'HTTP') {
        /** See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Evolution_of_HTTP */
        $Trigger((
            ($CIDRAM['Config']['httpver']['http_zero_nine'] && $Major === 0 && $Minor === 9) ||
            ($CIDRAM['Config']['httpver']['http_zero_x'] && $Major === 0 && $Minor !== 9) ||
            ($CIDRAM['Config']['httpver']['http_one_zero'] && $Major === 1 && $Minor === 0) ||
            ($CIDRAM['Config']['httpver']['http_one_one'] && $Major === 1 && $Minor === 1) ||
            ($CIDRAM['Config']['httpver']['http_one_two'] && $Major === 1 && $Minor === 2) ||
            ($CIDRAM['Config']['httpver']['http_one_three'] && $Major === 1 && $Minor === 3) ||
            ($CIDRAM['Config']['httpver']['http_one_x'] && $Major === 1 && $Minor !== 0 && $Minor !== 1 && $Minor !== 2 && $Minor !== 3) ||
            ($CIDRAM['Config']['httpver']['http_two_zero'] && $Major === 2 && $Minor === 0) ||
            ($CIDRAM['Config']['httpver']['http_two_x'] && $Major === 2 && $Minor !== 0) ||
            ($CIDRAM['Config']['httpver']['http_three_zero'] && $Major === 3 && $Minor === 0) ||
            ($CIDRAM['Config']['httpver']['http_three_x'] && $Major === 3 && $Minor !== 0) ||
            ($CIDRAM['Config']['httpver']['http_other'] && $Major !== 0 && $Major !== 1 && $Major !== 2 && $Major !== 3)
        ), 'Protocol denied (' . $Rebuilt . ')', $CIDRAM['Config']['httpver']['reason_message']);
    } elseif ($Protocol === 'SHTTP') {
        $Trigger((
            ($CIDRAM['Config']['httpver']['shttp_one_three'] && $Major === 1 && $Minor === 3) ||
            ($CIDRAM['Config']['httpver']['shttp_other'] && !($Major === 1 && $Minor === 3))
        ), 'Protocol denied (' . $Rebuilt . ')', $CIDRAM['Config']['httpver']['reason_message']);
    } elseif ($Protocol === 'SPDY') {
        $Trigger((
            ($CIDRAM['Config']['httpver']['spdy_three_zero'] && $Major === 3 && $Minor === 0) ||
            ($CIDRAM['Config']['httpver']['spdy_three_one'] && $Major === 3 && $Minor === 1) ||
            ($CIDRAM['Config']['httpver']['spdy_other'] && ($Major !== 3 || ($Minor !== 0 && $Minor !== 1)))
        ), 'Protocol denied (' . $Rebuilt . ')', $CIDRAM['Config']['httpver']['reason_message']);
    } elseif ($Protocol === 'IRC') {
        /** See: https://tools.ietf.org/html/rfc7230 */
        $Trigger((
            ($CIDRAM['Config']['httpver']['irc_six_nine'] && $Major === 6 && $Minor === 9) ||
            ($CIDRAM['Config']['httpver']['irc_other'] && !($Major === 6 && $Minor === 9))
        ), 'Protocol denied (' . $Rebuilt . ')', $CIDRAM['Config']['httpver']['reason_message']);
    } elseif ($Protocol === 'RTA') {
        $Trigger((
            ($CIDRAM['Config']['httpver']['rta_xeleven'] && $_SERVER['SERVER_PROTOCOL'] === 'RTA/x11') ||
            ($CIDRAM['Config']['httpver']['rta_other'] && $_SERVER['SERVER_PROTOCOL'] !== 'RTA/x11')
        ), 'Protocol denied (' . $Rebuilt . ')', $CIDRAM['Config']['httpver']['reason_message']);
    } else {
        $Trigger($CIDRAM['Config']['httpver']['empty_unfamiliar'], 'Protocol denied (' . $Rebuilt . ')', $CIDRAM['Config']['httpver']['reason_message']);
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
