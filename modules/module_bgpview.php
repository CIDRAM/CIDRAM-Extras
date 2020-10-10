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
 * This file: BGPView module (last modified: 2020.09.12).
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
    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Local BGPView cache entry expiry time (successful lookups). */
    $Expiry = $CIDRAM['Now'] + 604800;

    /** Build local BGPView cache if it doesn't already exist. */
    $CIDRAM['InitialiseCacheSection']('BGPView');

    $InCache = false;

    /** Expand factors for this origin. */
    $Expanded = [$CIDRAM['ExpandIPv4']($CIDRAM['BlockInfo']['IPAddr']), $CIDRAM['ExpandIPv6']($CIDRAM['BlockInfo']['IPAddr'])];

    /** Check whether we've already performed a lookup for this origin. */
    foreach ($Expanded as $Factors) {
        if (!is_array($Factors)) {
            continue;
        }
        foreach ($Factors as $Factor) {
            if (!isset($CIDRAM['BGPView'][$Factor])) {
                continue;
            }
            $InCache = true;
            break 2;
        }
    }

    /** Prepare to perform a new lookup if none for this origin have been cached yet. */
    if (!$InCache) {
        $Lookup = $CIDRAM['Request']('https://api.bgpview.io/ip/' . $CIDRAM['BlockInfo']['IPAddr']);
        $Lookup = (
            substr($Lookup, 0, 63) === '{"status":"ok","status_message":"Query was successful","data":{' &&
            substr($Lookup, -2) === '}}'
        ) ? json_decode($Lookup, true) : false;
        $Low = strpos($CIDRAM['BlockInfo']['IPAddr'], ':') !== false ? 128 : 32;
        $CIDRAM['BGPView'][$CIDRAM['BlockInfo']['IPAddr'] . '/' . $Low] = ['ASN' => -1, 'CC' => 'XX', 'Time' => $Expiry];
        $CIDRAM['BGPView-Modified'] = true;
        if (is_array($Lookup) && isset($Lookup['data'])) {
            if (isset($Lookup['data']['prefixes']) && is_array($Lookup['data']['prefixes'])) {
                foreach ($Lookup['data']['prefixes'] as $Prefix) {
                    $Factor = isset($Prefix['prefix']) ? $Prefix['prefix'] : false;
                    $ASN = isset($Prefix['asn']['asn']) ? $Prefix['asn']['asn'] : false;
                    $CC = isset($Prefix['asn']['country_code']) ? $Prefix['asn']['country_code'] : 'XX';
                    if ($Factor && $ASN) {
                        $CIDRAM['BGPView'][$Factor] = ['ASN' => $ASN, 'CC' => $CC, 'Time' => $Expiry];
                    }
                }
            }
            if (
                isset($Lookup['data']['rir_allocation']) &&
                is_array($Lookup['data']['rir_allocation']) &&
                isset($Lookup['data']['rir_allocation']['country_code'], $Lookup['data']['rir_allocation']['prefix'])
            ) {
                $Prefix = $Lookup['data']['rir_allocation']['prefix'];
                if (isset($CIDRAM['BGPView'][$Prefix])) {
                    $CIDRAM['BGPView'][$Prefix]['CC'] = $Lookup['data']['rir_allocation']['country_code'];
                } else {
                    $CIDRAM['BGPView'][$Prefix] = ['CC' => $Lookup['data']['rir_allocation']['country_code']];
                }
            }
        }
    }

    /** Process lookup results for this origin and act as per configured. */
    foreach ($Expanded as $Factors) {
        if (!is_array($Factors)) {
            continue;
        }
        foreach ($Factors as $Factor) {
            if (!isset($CIDRAM['BGPView'][$Factor])) {
                continue;
            }

            /** Act based on ASN. */
            if (!empty($CIDRAM['BGPView'][$Factor]['ASN'])) {
                /** Populate ASN lookup information. */
                if ($CIDRAM['BGPView'][$Factor]['ASN'] > 0) {
                    $CIDRAM['BlockInfo']['ASNLookup'] = $CIDRAM['BGPView'][$Factor]['ASN'];
                }

                /** Origin is whitelisted. */
                if ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['ASN'], $CIDRAM['Config']['bgpview']['whitelisted_asns'])) {
                    $CIDRAM['ZeroOutBlockInfo'](true);
                    break 2;
                }

                /** Origin is blocked. */
                if ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['ASN'], $CIDRAM['Config']['bgpview']['blocked_asns'])) {
                    $CIDRAM['BlockInfo']['ReasonMessage'] = $CIDRAM['L10N']->getString('ReasonMessage_Generic');
                    if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
                        $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
                    }
                    $CIDRAM['BlockInfo']['WhyReason'] .= sprintf(
                        '%s (BGPView, "%d")',
                        $CIDRAM['L10N']->getString('Short_Generic'),
                        $CIDRAM['BGPView'][$Factor]['ASN']
                    );
                    if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
                        $CIDRAM['BlockInfo']['Signatures'] .= ', ';
                    }
                    $CIDRAM['BlockInfo']['Signatures'] .= $Factor;
                    $CIDRAM['BlockInfo']['SignatureCount']++;
                }
            }

            /** Act based on CC. */
            if (!empty($CIDRAM['BGPView'][$Factor]['CC']) && empty($CCDone)) {
                /** Populate country code lookup information. */
                if ($CIDRAM['BGPView'][$Factor]['CC'] !== 'XX') {
                    $CIDRAM['BlockInfo']['CCLookup'] = $CIDRAM['BGPView'][$Factor]['CC'];
                    $CCDone = true;
                }

                /** Origin is whitelisted. */
                if ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['CC'], $CIDRAM['Config']['bgpview']['whitelisted_ccs'])) {
                    $CIDRAM['ZeroOutBlockInfo'](true);
                    break 2;
                }

                /** Origin is blocked. */
                if ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['CC'], $CIDRAM['Config']['bgpview']['blocked_ccs'])) {
                    $CIDRAM['BlockInfo']['ReasonMessage'] = 'No access allowed from ' . $CIDRAM['BGPView'][$Factor]['CC'] . '.';
                    if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
                        $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
                    }
                    $CIDRAM['BlockInfo']['WhyReason'] .= sprintf('CC (BGPView, "%s")', $CIDRAM['BGPView'][$Factor]['CC']);
                    if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
                        $CIDRAM['BlockInfo']['Signatures'] .= ', ';
                    }
                    $CIDRAM['BlockInfo']['Signatures'] .= $Factor;
                    $CIDRAM['BlockInfo']['SignatureCount']++;
                }
            }
        }
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
