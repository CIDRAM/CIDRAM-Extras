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
 * This file: Pinterest verifier (last modified: 2017.11.26).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Is it claiming to be Pinterest? */
if (strpos($CIDRAM['BlockInfo']['UALC'], 'pinterest') !== false) {

    /** Preserve trackable. */
    $Trackable = $CIDRAM['Trackable'];
    $CIDRAM['Trackable'] = true;

    /**
     * Verify it.
     * See: https://help.pinterest.com/en/articles/about-pinterest-crawler-0
     */
    $Success = $CIDRAM['DNS-Reverse-Forward'](['.pinterest.com'], 'Pinterest');

    /** Whitelist if necessary and restore trackable. */
    if (!$CIDRAM['Trackable'] || (!$Success && substr($CIDRAM['BlockInfo']['IPAddr'], 0, 7) === '54.236.')) {
        $CIDRAM['Whitelisted'] = true;
        $CIDRAM['BlockInfo']['Signatures'] = $CIDRAM['BlockInfo']['ReasonMessage'] = $CIDRAM['BlockInfo']['WhyReason'] = '';
        $CIDRAM['BlockInfo']['SignatureCount'] = 0;
        $CIDRAM['Trackable'] = $Trackable;
    }

}
