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
 * This file: Template module file for CIDRAM (last modified: 2021.04.29).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM') && !defined('CIDRAM-L')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Safety. */
if (!isset($CIDRAM['ModuleResCache'])) {
    $CIDRAM['ModuleResCache'] = [];
}

/**
 * Defining as closure for later recall (one param; no return value).
 *
 * @param int $Infractions The number of infractions incurred thus far.
 */
$CIDRAM['ModuleResCache'][$Module] = function ($Infractions = 0) use (&$CIDRAM) {
    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** Inherit bypass closure (see functions.php). */
    $Bypass = $CIDRAM['Bypass'];

    // All the following examples and guidelines are based on the assumption that
    // you've not modified the default signature trigger or signature bypass
    // closures, and that you're not using something else entirely to handle your
    // signatures.

    // Note that almost any variable defined by CIDRAM, and almost any variable
    // that exists within the current memory instance, can be accessed, leveraged
    // and modified by modules. The most common variables that you're likely to
    // ever be using are these (and of course, you can define your own, too):

    // $_POST       - See: http://php.net/manual/en/reserved.variables.post.php
    // $_GET        - See: http://php.net/manual/en/reserved.variables.get.php
    // $_SERVER     - See: http://php.net/manual/en/reserved.variables.server.php

    // $CIDRAM['BlockInfo']['IPAddr']
    //              - Represents the IP address associated with the current request
    //                instance.
    // $CIDRAM['BlockInfo']['Query']
    //              - Exactly the same as $_SERVER['QUERY_STRING'].
    // $CIDRAM['BlockInfo']['Referrer']
    //              - Exactly the same as $_SERVER['HTTP_REFERER'].
    // $CIDRAM['BlockInfo']['UA']
    //              - Exactly the same as $_SERVER['HTTP_USER_AGENT'].
    // $CIDRAM['BlockInfo']['ReasonMessage']
    //              - The longer, friendlier, human-readable message presented to
    //                the user/client when they're blocked, and included in the
    //                logfiles.
    // $CIDRAM['BlockInfo']['SignatureCount']
    //              - The total number of signatures triggered thus far in the
    //                request instance.
    // $CIDRAM['BlockInfo']['Signatures']
    //              - A list of the identifiers used by each signature triggered in
    //                the request instance.
    // $CIDRAM['BlockInfo']['WhyReason']
    //              - The shorter, slightly less friendly message included in the
    //                logfile entry when the request instance is blocked.
    // $CIDRAM['BlockInfo']['UALC']
    //              - $CIDRAM['BlockInfo']['UA'] converted to lower-case.
    // $CIDRAM['BlockInfo']['rURI']
    //              - The complete requested URI/URL, reconstructed by CIDRAM.
    // $CIDRAM['Hostname']
    //             - The hostname associated with the IP from which the request
    //               instance has originated.
    //               ** IMPORTANT: Mightn't always be available (see below for details)! **

    // If you want to write signatures and/or bypasses which work with the hostname
    // associated with the IP from which the request instance has originated, keep
    // the following code block. If not, it can be safely removed.

    /** Fetch hostname. */
    if (empty($CIDRAM['Hostname'])) {
        $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
    }

    // As per the docBlock comments included earlier in this document pertaining to
    // the $Trigger and $Bypass closures, the first parameter (in either case)
    // should consist of something which can be evaluated for truthiness (meaning,
    // something which can be considered to be either "true" or "false"). This
    // could be almost anything... A simple boolean variable, a string, a logical
    // comparison, a function call, some math, etc. Basically, this should be what
    // you're actually checking for, representing your logic for determining under
    // what circumstances the signature should be considered to be "triggered", and
    // therefore under what circumstances the request instance should be blocked.
    // The second parameter sould be a short description and/or ID for your
    // signature or bypass. In the case of signatures which use $Trigger, the third
    // parameter (which is optional) provides a way to include a friendlier, more
    // human readable reason and/or message, which can be displayed to the
    // user/client when they're blocked, to inform them of why they've been blocked.
    // The next and final parameter (fourth for $Trigger, or third for $Bypass;
    // also optional) should be an array, containing configuration values to apply
    // to CIDRAM for blocked request instances.

    // Example 1: Block any UA (user agent) which contains the word "Foobar".
    $Trigger(strpos($CIDRAM['BlockInfo']['UA'], 'Foobar') !== false, 'No-Foobar-001', 'No foobar here. Foobar not here.');

    // However, there's a problem: "$CIDRAM['BlockInfo']['UA']" is case-sensitive!
    // Therefore.. Example 2: Block any UA which contains the word "foobar",
    // irrespective of case:
    $Trigger(strpos($CIDRAM['BlockInfo']['UALC'], 'foobar') !== false, 'No-Foobar-001-MkII', 'No foobar here. Foobar not here.');

    // But what if someone decides to split it up with random spaces..? Let's make
    // our own custom variable to account for this, which we can then use to write
    // another signature. We'll call it "$UANoSpace", and leverage preg_match() to
    // create it:
    $UANoSpace = preg_replace('/\s/', '', $CIDRAM['BlockInfo']['UALC']);

    // Example 3: Now we can catch things like "f o o b a r":
    $Trigger(strpos($UANoSpace, 'foobar') !== false, 'No-Foobar-001-MkIII', 'No foobar here. Foobar not here.');

    // But what if they start doing things like using "leetspeak"/"13375934k"(/etc)
    // to hide their true intended UA? Well.. We can use regular expressions to
    // solve that problem (example 4):
    $Trigger(preg_match('/f[0o]{2}b[4a]r/', $UANoSpace), 'No-Foobar-001-MkIV', 'No foobar here. Foobar not here.');

    // But whoops! One of our users happens to use an obscure browser that
    // identifies itself as "FoobarBrowse/v1.0.0", and they've just complained
    // about being blocked! What can we do?! Well.. If their UA is consistent, that
    // should actually be pretty easy to deal with: We can allow their UA through,
    // while blocking everything else which contains foobar, by doing something
    // like this (example 5):
    $Trigger(
        $CIDRAM['BlockInfo']['UA'] !== 'FoobarBrowse/v1.0.0' && preg_match(
            '/f[0o]{2}b[4a]r/',
            $UANoSpace
        ),
        'No-Foobar-001-MkIV',
        'No foobar here. Foobar not here.'
    );

    // Alternatively.. If they've been blocked by a signature that exists in a
    // different module, or if, for whatever reason, they've already been blocked
    // by some signature or another and we're in a situation whereby we need to
    // undo this, we can just write a bypass for them (example 6):
    $Bypass($CIDRAM['BlockInfo']['UA'] === 'FoobarBrowse/v1.0.0', 'FoobarBrowser-Bypass');

    // Note that in example 5, I've used "!==", but in example 6, I've used "===".
    // This is because we want the signature in example 5 to trigger only if their
    // UA does *NOT* match "FoobarBrowse/v1.0.0", whereas we want to bypass in
    // example 6 to trigger if their UA *DOES* match "FoobarBrowse/v1.0.0" (it may
    // appear complex on the surface, but the logic behind all of this is actually
    // really stupidly simple). :-)

    // Now let's try to detect a leetspeakified foobar, split by spaces and mixed
    // cases as per how we've done in example 4 and example 5, but let's try to
    // detect it in the query part of the request. First, let's create a new
    // variable to do with the query what we've done with the UA:
    $QueryNoSpace = preg_replace('/\s/', '', strtolower($CIDRAM['BlockInfo']['Query']));

    // From here, it's just a matter of.. (example 7):
    $Trigger(preg_match('/f[0o]{2}b[4a]r/', $QueryNoSpace), 'No-Foobar-001-MkV', 'No foobar here. Foobar not here.');

    // Something *slightly* more complex: Let's block any requests which claim to
    // have been referred from these (imaginary) websites: "foobar.com",
    // "foobot.com", "example.tld", and "ex4mpl3.tld", let's do it all in
    // lower-case, and let's do it in a single operation, without creating any new
    // variables (example 8):
    $Trigger(preg_match('/(?:foob(ar|ot)\.com|ex[4a]mpl[3e]\.tld)/i', $CIDRAM['BlockInfo']['Referrer']), 'No-Foobar-001-MkVI', 'No foobar here. Foobar not here.');

    // A few simple "gotchas":
    // - The reason I've used "!== false" within the first parameter when using
    //   strpos, is because strpos will return false when a sub-string is not found
    //   within a string (i.e., the needle is not found within the haystack), but it
    //   will return 0 if the needle exists at the beginning of the haystack (or at
    //   character position 0), and 0 also evaluates as false (i.e., the truthiness
    //   for 0, is false). Using "!== false" ensures that our signatures will only
    //   be triggered if the needle truly does not exist within the haystack.
    // - CIDRAM uses "closures"; It does not use "functions". Using "Trigger()"
    //   instead of "$Trigger()" will result in errors, and will not result in the
    //   creation of proper, correct, operable signatures.
    // - Each module operates within its own scope, and they do not share scopes.
    //   The "$CIDRAM" array-variable, which contains most of the working data for
    //   CIDRAM in active memory, is referenced into each scope, and therefore, any
    //   changes made to "$CIDRAM" by one module, will be accessible by every other
    //   module (and also, will effect CIDRAM itself). However, any *other*
    //   variables created and/or modified by a module, *won't* be accessible by
    //   any other modules (for example; if I create two new variables, one named
    //   "$Foo" and another named "$CIDRAM['Foo']", "$Foo" will not exist anymore
    //   by the time the next subsequent module is executed, but "$CIDRAM['Foo']"
    //   will continue to exist until CIDRAM completes its entire execution
    //   process).
    // - Modules won't do anything if they're not being called by the script! Don't
    //   forget to actually reference them in the modules directive of the
    //   configuration ("signatures->modules").
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]($Infractions);
