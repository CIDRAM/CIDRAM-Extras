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
 * This file: BGPView module (last modified: 2019.12.23).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

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
    $CIDRAM['BGPView'][$CIDRAM['BlockInfo']['IPAddr'] . '/32'] = ['ASN' => -1, 'CC' => 'XX'];
    $CIDRAM['BGPView-Modified'] = true;
    if (isset($Lookup['data']['prefixes']) && is_array($Lookup['data']['prefixes'])) {
        foreach ($Lookup['data']['prefixes'] as $Prefix) {
            $Factor = isset($Prefix['prefix']) ? $Prefix['prefix'] : '';
            $ASN = isset($Prefix['asn']['asn']) ? $Prefix['asn']['asn'] : '';
            $CC = isset($Prefix['asn']['country_code']) ? $Prefix['asn']['country_code'] : '';
            if ($Factor && $ASN) {
                $CIDRAM['BGPView'][$Factor] = ['ASN' => $ASN, 'CC' => $CC];
            }
        }
    }
}

/** Prepare to perform a new lookup if none for this origin have been cached yet. */
foreach ($Expanded as $Factors) {
    if (!is_array($Factors)) {
        continue;
    }
    foreach ($Factors as $Factor) {
        if (!isset($CIDRAM['BGPView'][$Factor])) {
            continue;
        }

        /** Act based on ASN. */
        if (isset($CIDRAM['BGPView'][$Factor]['ASN'])) {
            if ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['ASN'], $CIDRAM['Config']['bgpview']['whitelisted_asns'])) {
                /** Origin is whitelisted. */
                $CIDRAM['ZeroOutBlockInfo'](true);
                break 2;
            } elseif ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['ASN'], $CIDRAM['Config']['bgpview']['blocked_asns'])) {
                /** Origin is blocked. */
                $CIDRAM['BlockInfo']['ReasonMessage'] = $CIDRAM['L10N']->getString('ReasonMessage_Generic');
                if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
                    $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
                }
                $CIDRAM['BlockInfo']['WhyReason'] .= $CIDRAM['L10N']->getString('Short_Generic') . ' (BGPView)';
                if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
                    $CIDRAM['BlockInfo']['Signatures'] .= ', ';
                }
                $CIDRAM['BlockInfo']['Signatures'] .= $Factor;
                $CIDRAM['BlockInfo']['SignatureCount']++;
            }
        }

        /** Act based on CC. */
        if (isset($CIDRAM['BGPView'][$Factor]['CC'])) {
            if ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['CC'], $CIDRAM['Config']['bgpview']['whitelisted_ccs'])) {
                /** Origin is whitelisted. */
                $CIDRAM['ZeroOutBlockInfo'](true);
                break 2;
            } elseif ($CIDRAM['in_csv']($CIDRAM['BGPView'][$Factor]['CC'], $CIDRAM['Config']['bgpview']['blocked_ccs'])) {
                /** Origin is blocked. */
                $CIDRAM['BlockInfo']['ReasonMessage'] = 'No access allowed from ' . $CIDRAM['BGPView'][$Factor]['CC'] . '.';
                if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
                    $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
                }
                $CIDRAM['BlockInfo']['WhyReason'] .= 'CC (BGPView)';
                if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
                    $CIDRAM['BlockInfo']['Signatures'] .= ', ';
                }
                $CIDRAM['BlockInfo']['Signatures'] .= $Factor;
                $CIDRAM['BlockInfo']['SignatureCount']++;
            }
        }

    }
}
