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
 * This file: Project Honeypot module (last modified: 2021.03.21).
 *
 * False positive risk (an approximate, rough estimate only): « [ ]Low [x]Medium [ ]High »
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
    /**
     * Project Honeypot's HTTP:BL API currently can only handle IPv4 (i.e., not
     * IPv6). So, we shouldn't continue for the instance if the request isn't
     * originating from an IPv4 connection.
     */
    if (empty($CIDRAM['LastTestIP']) || $CIDRAM['LastTestIP'] !== 4) {
        return;
    }

    /**
     * We can't perform lookups without an API key, so we should check for that,
     * too.
     */
    if (empty($CIDRAM['Config']['projecthoneypot']['api_key'])) {
        return;
    }

    /** Normalised, lower-cased request URI; Used to determine whether the module needs to do anything for the request. */
    $LCURI = preg_replace('/\s/', '', strtolower($CIDRAM['BlockInfo']['rURI']));

    /** If the request isn't attempting to access a sensitive page (login, registration page, etc), exit. */
    if (!$CIDRAM['Config']['projecthoneypot']['lookup_everything'] && !$CIDRAM['IsSensitive']($LCURI)) {
        return;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Local Project Honeypot cache entry expiry time (successful lookups). */
    $Expiry = $CIDRAM['Now'] + 604800;

    /** Local Project Honeypot cache entry expiry time (failed lookups). */
    $ExpiryFailed = $CIDRAM['Now'] + 3600;

    /** Build local Project Honeypot cache if it doesn't already exist. */
    $CIDRAM['InitialiseCacheSection']('Project Honeypot');

    /**
     * Only execute if not already blocked for some other reason, if the IP is valid, if not from a private or reserved
     * range, and if the lookup limit hasn't already been exceeded (reduces superfluous lookups).
     */
    if (
        isset($CIDRAM['Project Honeypot']['429']) ||
        !$CIDRAM['HonourLookup']() ||
        filter_var($CIDRAM['BlockInfo']['IPAddr'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
    ) {
        return;
    }

    /** Executed if there aren't any cache entries corresponding to the IP of the request. */
    if (!isset($CIDRAM['Project Honeypot'][$CIDRAM['BlockInfo']['IPAddr']])) {
        /** Build the lookup query. */
        $Lookup = preg_replace(
            '~^(\d+)\.(\d+)\.(\d+)\.(\d+)$~',
            $CIDRAM['Config']['projecthoneypot']['api_key'] . '.\4.\3.\2.\1.dnsbl.httpbl.org',
            $CIDRAM['BlockInfo']['IPAddrResolved'] ?: $CIDRAM['BlockInfo']['IPAddr']
        );

        /** Perform Project Honeypot lookup. */
        $Data = $CIDRAM['DNS-Resolve']($Lookup, $CIDRAM['Config']['projecthoneypot']['timeout_limit']);

        if ($CIDRAM['Request']->MostRecentStatusCode === 429) {
            /** Lookup limit has been exceeded. */
            $CIDRAM['Project Honeypot']['429'] = ['Time' => $Expiry];
        } else {
            /**
             * Validate or substitute.
             *
             * @link https://www.projecthoneypot.org/httpbl_api.php
             */
            if (preg_match('~^127\.\d+\.\d+\.\d+$~', $Data)) {
                $Data = explode('.', $Data);
                $Data = [
                    'Days since last activity' => $Data[1],
                    'Threat score' => $Data[2],
                    'Type of visitor' => $Data[3],
                    'Time' => $Expiry
                ];
            } else {
                $Data = [
                    'Days since last activity' => -1,
                    'Threat score' => -1,
                    'Type of visitor' => -1,
                    'Time' => $ExpiryFailed
                ];
            }

            /** Generate local Project Honeypot cache entry. */
            $CIDRAM['Project Honeypot'][$CIDRAM['BlockInfo']['IPAddr']] = $Data;
        }

        /** Cache update flag. */
        $CIDRAM['Project Honeypot-Modified'] = true;
    }

    /** Block the request if the IP is listed by Project Honeypot. */
    $Trigger((
        $CIDRAM['Project Honeypot'][$CIDRAM['BlockInfo']['IPAddr']]['Threat score'] >= $CIDRAM['Config']['projecthoneypot']['minimum_threat_score'] &&
        $CIDRAM['Project Honeypot'][$CIDRAM['BlockInfo']['IPAddr']]['Days since last activity'] <= $CIDRAM['Config']['projecthoneypot']['max_age_in_days']
    ), 'Project Honeypot Lookup', $CIDRAM['L10N']->getString('ReasonMessage_Generic') . '<br />' . sprintf(
        $CIDRAM['L10N']->getString('request_removal'),
        'https://www.projecthoneypot.org/ip_' . ($CIDRAM['BlockInfo']['IPAddrResolved'] ?: $CIDRAM['BlockInfo']['IPAddr'])
    ));
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
