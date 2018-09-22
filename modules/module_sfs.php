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
 * This file: Stop Forum Spam module (last modified: 2018.09.22).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Normalised, lower-cased request URI; Used to determine whether the module needs to do anything for the request. */
$LCURI = preg_replace('/\s/', '', strtolower($CIDRAM['BlockInfo']['rURI']));

/** If the request is attempting to access a sensitive page (login, registration page, etc), proceed. */
if (preg_match(
    '~(?:/(comprofiler|user)/(login|register)|=(activate|login|regist(er|rat' .
    'ion)|signup)|act(ion)?=(edit|reg)|(activate|confirm|login|newuser|reg(i' .
    'st(er|ration))?|sign(in|up))(\.php|=)|special:userlogin&|verifyemail|wp' .
    '-comments-post)~',
$LCURI)) {

    /** Build local SFS cache if it doesn't already exist. */
    if (!isset($CIDRAM['Cache']['SFS'])) {
        $CIDRAM['Cache']['SFS'] = [];
    }

    /** Local SFS cache entry expiry time (successful lookups). */
    $Expiry = $CIDRAM['Now'] + 604800;

    /** Local SFS cache entry expiry time (failed lookups). */
    $ExpiryFailed = $CIDRAM['Now'] + 3600;

    /** Clear outdated SFS cache entries. */
    $CIDRAM['ClearFromCache']('SFS');

    /**
     * Only execute if not already blocked for some other reason, and if the IP is valid, and not from a private or
     * reserved range (reduces superfluous lookups).
     */
    if (
        !$CIDRAM['BlockInfo']['SignatureCount'] &&
        filter_var($_SERVER[$CIDRAM['IPAddr']], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
    ) {

        /** Executed if there aren't any cache entries corresponding to the IP of the request. */
        if (!isset($CIDRAM['Cache']['SFS'][$_SERVER[$CIDRAM['IPAddr']]])) {

            /** Perform SFS lookup. */
            $Lookup = $CIDRAM['Request']('https://www.stopforumspam.com/api', [
                'ip' => $_SERVER[$CIDRAM['IPAddr']],
                'f' => 'serial'
            ]);

            /** Generate local SFS cache entry. */
            $CIDRAM['Cache']['SFS'][$_SERVER[$CIDRAM['IPAddr']]] = (
                strpos($Lookup, 's:7:"success";') !== false && strpos($Lookup, 's:2:"ip";') !== false
            ) ? ['Listed' => (strpos($Lookup, '"appears";i:1;') !== false), 'Time' => $Expiry] : ['Listed' => false, 'Time' => $ExpiryFailed];

            /** Cache has been modified. */
            $CIDRAM['CacheModified'] = true;

        }

        /** Block the request if the IP is listed by SFS. */
        $Trigger(
            !empty($CIDRAM['Cache']['SFS'][$_SERVER[$CIDRAM['IPAddr']]]['Listed']),
            'SFS Lookup',
            $CIDRAM['lang']['ReasonMessage_Banned']
        );

    }

}
