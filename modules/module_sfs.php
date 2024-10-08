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
 * This file: Stop Forum Spam module (last modified: 2024.08.13).
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

    /**
     * Normalised, lower-cased request URI; Used to determine whether the
     * module needs to do anything for the request.
     */
    $LCURI = preg_replace('/\s/', '', strtolower($CIDRAM['BlockInfo']['rURI']));

    /**
     * If the request isn't attempting to access a sensitive page (login,
     * registration page, etc), exit.
     */
    if (!$CIDRAM['IsSensitive']($LCURI)) {
        return;
    }

    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Marks for use with reCAPTCHA and hCAPTCHA. */
    $EnableCaptcha = ['recaptcha' => ['enabled' => true], 'hcaptcha' => ['enabled' => true]];

    /** Local SFS cache entry expiry time (successful lookups). */
    $Expiry = $CIDRAM['Now'] + 604800;

    /** Local SFS cache entry expiry time (failed lookups). */
    $ExpiryFailed = $CIDRAM['Now'] + 3600;

    /** Build local SFS cache if it doesn't already exist. */
    $CIDRAM['InitialiseCacheSection']('SFS');

    /**
     * Only execute if not already blocked for some other reason, if the IP is
     * valid, if not from a private or reserved range, and if the lookup limit
     * hasn't already been exceeded (reduces superfluous lookups).
     */
    if (
        isset($CIDRAM['SFS']['429']) ||
        !$CIDRAM['HonourLookup']() ||
        filter_var($CIDRAM['BlockInfo']['IPAddr'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
    ) {
        return;
    }

    /** Executed if there aren't any cache entries corresponding to the IP of the request. */
    if (!isset($CIDRAM['SFS'][$CIDRAM['BlockInfo']['IPAddr']])) {
        /** Perform SFS lookup. */
        $Lookup = $CIDRAM['Request']('https://www.stopforumspam.com/api', [
            'ip' => $CIDRAM['BlockInfo']['IPAddr'],
            'f' => 'serial'
        ], $CIDRAM['Config']['sfs']['timeout_limit']);

        if ($CIDRAM['Request']->MostRecentStatusCode === 429) {
            /** Lookup limit has been exceeded. */
            $CIDRAM['SFS']['429'] = ['Time' => $Expiry];
        } else {
            /** Generate local SFS cache entry. */
            $CIDRAM['SFS'][$CIDRAM['BlockInfo']['IPAddr']] = (
                strpos($Lookup, 's:7:"success";') !== false &&
                strpos($Lookup, 's:2:"ip";') !== false
            ) ? [
                'Listed' => (strpos($Lookup, '"appears";i:1;') !== false),
                'Time' => $Expiry
            ] : [
                'Listed' => false,
                'Time' => $ExpiryFailed
            ];
        }

        /** Cache update flag. */
        $CIDRAM['SFS-Modified'] = true;
    }

    /** Block the request if the IP is listed by SFS. */
    $Trigger(
        !empty($CIDRAM['SFS'][$CIDRAM['BlockInfo']['IPAddr']]['Listed']),
        'SFS Lookup',
        $CIDRAM['L10N']->getString('ReasonMessage_Spam') . '<br />' . sprintf($CIDRAM['L10N']->getString('request_removal'), 'https://www.stopforumspam.com/removal'),
        $CIDRAM['Config']['sfs']['offer_captcha'] ? $EnableCaptcha : []
    );
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
