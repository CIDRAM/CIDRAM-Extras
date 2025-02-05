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
 * This file: AbuseIPDB module (last modified: 2025.02.05).
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
    /** Guard. */
    if (empty($CIDRAM['BlockInfo']['IPAddr'])) {
        return;
    }

    /**
     * We can't perform lookups without an API key, so we should check for
     * that, too.
     */
    if (empty($CIDRAM['Config']['abuseipdb']['api_key'])) {
        return;
    }

    /**
     * Normalised, lower-cased request URI; Used to determine whether the
     * module needs to do anything for the request.
     */
    $LCURI = preg_replace('/\s/', '', strtolower($CIDRAM['BlockInfo']['rURI']));

    /**
     * If the request isn't attempting to access a sensitive page (login,
     * registration page, etc), exit.
     */
    if (!$CIDRAM['Config']['abuseipdb']['lookup_everything'] && !$CIDRAM['IsSensitive']($LCURI)) {
        return;
    }

    /**
     * Only execute if not already blocked for some other reason, if the IP is
     * valid, if not from a private or reserved range, and if the lookup limit
     * hasn't already been exceeded (reduces superfluous lookups).
     */
    if (
        isset($CIDRAM['AbuseIPDB']['429']) ||
        !$CIDRAM['HonourLookup']() ||
        filter_var($CIDRAM['BlockInfo']['IPAddr'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
    ) {
        return;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Marks for use with reCAPTCHA and hCAPTCHA. */
    $EnableCaptcha = ['recaptcha' => ['enabled' => true], 'hcaptcha' => ['enabled' => true]];

    /** Local AbuseIPDB cache entry expiry time (successful lookups). */
    $Expiry = $CIDRAM['Now'] + 604800;

    /** Local AbuseIPDB cache entry expiry time (failed lookups). */
    $ExpiryFailed = $CIDRAM['Now'] + 3600;

    /** Build local AbuseIPDB cache if it doesn't already exist. */
    $CIDRAM['InitialiseCacheSection']('AbuseIPDB');

    /** Executed if there aren't any cache entries corresponding to the IP of the request. */
    if (!isset($CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']])) {
        /** Perform AbuseIPDB lookup. */
        $Lookup = $CIDRAM['Request'](
            'https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode($CIDRAM['BlockInfo']['IPAddr']) . '&maxAgeInDays=' . $CIDRAM['Config']['abuseipdb']['max_age_in_days'],
            [],
            $CIDRAM['Config']['abuseipdb']['timeout_limit'],
            ['Key: ' . $CIDRAM['Config']['abuseipdb']['api_key'], 'Accept: application/json']
        );

        if ($CIDRAM['Request']->MostRecentStatusCode === 429) {
            /** Lookup limit has been exceeded. */
            $CIDRAM['AbuseIPDB']['429'] = ['Time' => $Expiry];
        } else {
            /** Validate or substitute. */
            $Lookup = strpos($Lookup, '"abuseConfidenceScore":') !== false ? json_decode($Lookup, true) : [];

            /** Generate local AbuseIPDB cache entry. */
            $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']] = empty($Lookup['data']['abuseConfidenceScore']) ? [
                'abuseConfidenceScore' => 0,
                'Time' => $ExpiryFailed
            ] : [
                'abuseConfidenceScore' => $Lookup['data']['abuseConfidenceScore'],
                'Time' => $Expiry
            ];

            /** Total reports. */
            if (empty($Lookup['data']['totalReports'])) {
                $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['totalReports'] = 0;
            } else {
                $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['totalReports'] = $Lookup['data']['totalReports'];
            }

            /** Usage type. */
            if (!empty($Lookup['data']['usageType'])) {
                $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['usageType'] = $Lookup['data']['usageType'];
            }

            /** Check whether whitelisted. */
            $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['isWhitelisted'] = !empty($Lookup['data']['isWhitelisted']);
        }

        /** Cache update flag. */
        $CIDRAM['AbuseIPDB-Modified'] = true;
    }

    /** Block the request if the IP is listed by AbuseIPDB. */
    $Trigger(
        (
            !$CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['isWhitelisted'] &&
            $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['abuseConfidenceScore'] >= $CIDRAM['Config']['abuseipdb']['minimum_confidence_score'] &&
            $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['totalReports'] >= $CIDRAM['Config']['abuseipdb']['minimum_total_reports']
        ),
        'AbuseIPDB Lookup',
        $CIDRAM['L10N']->getString('ReasonMessage_Generic') . '<br />' . sprintf($CIDRAM['L10N']->getString('request_removal'), 'https://www.abuseipdb.com/takedown/' . $CIDRAM['BlockInfo']['IPAddr']),
        $CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['abuseConfidenceScore'] <= $CIDRAM['Config']['abuseipdb']['max_cs_for_captcha'] ? $EnableCaptcha : []
    );

    /** Build profiles. */
    if (
        $CIDRAM['Config']['abuseipdb']['build_profiles_from_usage_type'] &&
        !empty($CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['usageType'])
    ) {
        $CIDRAM['AddProfileEntry']($CIDRAM['AbuseIPDB'][$CIDRAM['BlockInfo']['IPAddr']]['usageType']);
    }
};

/** Add AbuseIPDB report handler. */
if ($CIDRAM['Config']['abuseipdb']['report_back'] && $CIDRAM['Config']['abuseipdb']['api_key'] !== '') {
    $CIDRAM['Reporter']->addHandler(function ($Report) use (&$CIDRAM) {
        $CIDRAM['InitialiseCacheSection']('RecentlyReported');
        if (
            isset($CIDRAM['RecentlyReported'][$Report['IP']]) ||
            ($CIDRAM['Config']['abuseipdb']['report_back'] === 2 && $CIDRAM['BlockInfo']['SignatureCount'] < 1)
        ) {
            return;
        }
        $Categories = [];
        foreach ($Report['Categories'] as $Category) {
            if ($Category > 2 && $Category < 24) {
                $Categories[] = $Category;
            }
        }
        if (!count($Categories)) {
            return;
        }
        $Categories = implode(',', $Categories);
        $Status = $CIDRAM['Request']('https://api.abuseipdb.com/api/v2/report', [
            'ip' => $Report['IP'],
            'categories' => $Categories,
            'comment' => $Report['Comments']
        ], $CIDRAM['Config']['abuseipdb']['timeout_limit'], [
            'Key: ' . $CIDRAM['Config']['abuseipdb']['api_key'],
            'Accept: application/json'
        ]);
        $CIDRAM['RecentlyReported'][$Report['IP']] = ['Status' => $Status, 'Time' => ($CIDRAM['Now'] + 900)];
        $CIDRAM['RecentlyReported-Modified'] = true;
        if (strpos($Status, '"ipAddress":"' . $Report['IP'] . '"') !== false && strpos($Status, '"errors":') === false) {
            if (!isset($CIDRAM['Report OK'])) {
                $CIDRAM['Report OK'] = 0;
            }
            $CIDRAM['Report OK']++;
        } else {
            if (!isset($CIDRAM['Report Failed'])) {
                $CIDRAM['Report Failed'] = 0;
            }
            $CIDRAM['Report Failed']++;
        }
    });
}

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
