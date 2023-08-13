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
 * This file: Optional security extras module (last modified: 2023.08.13).
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
    /** Inherit trigger closure (see functions.php). */
    $Trigger = $CIDRAM['Trigger'];

    /** The number of signatures triggered by this point in time. */
    $Before = isset($CIDRAM['BlockInfo']['SignaturesCount']) ? $CIDRAM['BlockInfo']['SignaturesCount'] : 0;

    $Trigger(count($_REQUEST) >= 500, 'Hack attempt', 'Too many request variables sent!'); // 2017.01.01

    /** Needed for some bypasses specific to WordPress (detects whether we're running as a WordPress plugin). */
    $is_WP_plugin = (defined('ABSPATH') || strtolower(str_replace("\\", '/', substr(__DIR__, -31))) === 'wp-content/plugins/cidram/vault');

    /** If enabled, block empty user agents. */
    if ($CIDRAM['Config']['extras']['block_empty_ua']) {
        $Trigger(preg_replace('~[^\w\d]~i', '', $CIDRAM['BlockInfo']['UA']) === '', 'Empty UA');
    }

    /** Inherit bypass closure (see functions.php). */
    $Bypass = $CIDRAM['Bypass'];

    /**
     * Signatures based on the reconstructed URI start from here.
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if ($CIDRAM['Config']['extras']['ruri'] && $CIDRAM['BlockInfo']['rURI']) {
        $LCNrURI = str_replace("\\", '/', strtolower($CIDRAM['BlockInfo']['rURI']));

        /** Directory traversal protection. */
        $Trigger(preg_match('~(?:/|%5[cf])\.{2,}(?:/|%5[cf])~i', $LCNrURI), 'Traversal attack'); // 2017.01.13

        /** Detect bad/dangerous/malformed requests. */
        $Trigger(preg_match('~(?:(/|%5[cf])\.(/|%5[cf])|(/|%5[cf]){3,}|[\x00-\x1f\x7f])~i', $LCNrURI), 'Bad request'); // 2017.01.13

        /** WordPress user enumeration (modified 2022.11.07). */
        if ($Trigger(preg_match('~\?author=\d+~i', $LCNrURI), 'WordPress user enumeration not allowed')) {
            $Bypass(
                strpos($LCNrURI, 'administrator/') !== false,
                'Joomla image inserting tool bypass (WordPress user enumeration conflict)'
            ) || $Bypass(
                strpos($LCNrURI, 'search.php?keywords=') !== false,
                'phpBB search bypass (WordPress user enumeration conflict)'
            );
        }

        $Trigger(strpos($LCNrURI, 'wp-print.php?script=1') !== false, 'WP hack attempt'); // 2017.10.07 mod 2023.08.10

        /** Probing for quarantined files. */
        if ($Trigger(preg_match('~\.[\da-z]{2,4}\.suspected(?:$|[/?])~', $LCNrURI), 'Probing for quarantined files')) {
            $CIDRAM['Reporter']->report([15], ['Caught probing for quarantined files.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2017.03.22 mod 2023.08.13

        /** Probing for unsecured backup files. */
        if ($Trigger(preg_match(
            '~(?:backup|(?:backup|docroot|htdocs|public_html|site|www)\.(?:gz|rar|tar(?:\.gz)?|zip)|d(?:atabase|b|ump)\.sql)(?:$|[/?])~',
            $LCNrURI
        ), 'Probing for unsecured backup files not allowed')) {
            $CIDRAM['Reporter']->report([15], ['Caught probing for unsecured backup files.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2023.08.13

        /** Probing for webshells/backdoors. */
        if ($Trigger(preg_match(
            '~old/wp-admin/install\.php|shell\?cd|' .
            'test/wp-includes/wlwmanifest\.xml|' .
            '(?:' .
            '\+theme\+/(?:error|index)|' .
            '\.w(?:ell-known|p-cli)/.*(?:about|install|moon|wp-login)|' .
            '0byte|0x|\d{3,5}[a-z]{3,5}|10+|991176|' .
            'admin-heade\d*|adminfuns|alfa(?:-rex|ioxi|new)\d*|anjas|apismtp|axx|' .
            'bak|bala|' .
            'c(?:9|10)\d+|casper[\da-z]+|(?:cgi-bin|css)/(?:moon|newgolden|radio|uploader|well-known|wp-login)|classsmtps|colors/blue/uploader|' .
            'd7|deadcode\d*|dkiz|' .
            'ee|' .
            'fddqradz|' .
            'gh[0o]st|glab-rare|gzismexv|' .
            'h[4a]x+[0o]r|h6ss|hanna1337|hehehe|htmlawedtest|' .
            'i\d{3,}[a-z]{2,}|icesword|indoxploit|ir7szrsouep|itsec|' .
            'lock0?360|lufix(?:-shell)?|' .
            'miin|my1|' .
            'orvx(?:-shell)?|' .
            'php(?:1|_niu_\d+)|poison|priv8|pzaiihfi|' .
            'rxr(?:_[\da-z]+)?|' .
            'session91|sh[3e]llx?\d*|shrift|sidwso|silic|skipper(?:shell)?|spammervip|sonarxleetxd|' .
            't62|themes/(?:finley/min|universal-news/www)|tinymce/langs/about|tk(?:_dencode_\d+)?|(?:tmp|wp-content)/vuln|topxoh/(?:drsx|wdr)|' .
            'unisibfu|upfile(?:_\(\d\))?|uploader_by_cloud7_agath|utchiha(?:_uploader)?|' .
            'vzlateam|' .
            'w0rdpr3ssnew|walker-nva|webshell-[a-z\d]+|widgets-nva|widwsisw|wloymzuk|wp-(?:2019|22|(?:admin|content|includes)/(?:cong|dropdown|repeater)|conflg|filemanager|setups|sigunq|p)|ws[ou](?:yanz)?(?:[\d.]*|[\da-z]{4,})|wwdv|' .
            'x{3,}|xiaom|xichang/x|x+l(?:\d+|eet(?:mailer|-shell)?x?)|xm(?:lrpcs|lrpz|rlpc)|xw|' .
            'yanz|' .
            'zone_hackbar(?:_beutify_other)?|' .
            '/src/util/php/(?:eval-stdin|kill)|' .
            '版iisspy|大马|一句话(?:木马|扫描脚本程序)?' .
            ')\.php[57]?(?:$|[/?])~',
            $LCNrURI
        ), 'Probing for webshells/backdoors')) {
            $CIDRAM['Reporter']->report([15, 20, 21], ['Caught probing for webshells/backdoors. Host might be compromised.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2023.08.13

        /** Probing for exposed Git data. */
        if ($Trigger(preg_match('~\.git(?:$|\W)~i', $LCNrURI), 'Probing for exposed git data')) {
            $CIDRAM['Reporter']->report([15, 21], ['Caught probing for exposed git data.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2022.06.05

        /** Probing for exposed SSH data. */
        if ($Trigger(preg_match('~^\.ssh(?:$|\W)~i', $LCNrURI), 'Probing for exposed SSH data')) {
            $CIDRAM['Reporter']->report([15, 22], ['Caught probing for exposed SSH data.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2022.06.05

        /** Probing for vulnerable routers. */
        if ($Trigger(preg_match('~(?:^|\W)HNAP1~i', $LCNrURI), 'Probing for vulnerable routers')) {
            $CIDRAM['Reporter']->report([15, 23], ['Caught probing for vulnerable routers.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2022.06.05

        /** Probing for vulnerable webapps. */
        if ($Trigger(preg_match('~cgi-bin/(?:web)?login\.cgi(?:$|\?)~i', $LCNrURI), 'Probing for vulnerable webapps')) {
            $CIDRAM['Reporter']->report([15, 21], ['Caught probing for vulnerable webapps.'], $CIDRAM['BlockInfo']['IPAddr']);
        } // 2022.06.05
    }

    /**
     * Query-based signatures start from here.
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if ($CIDRAM['Config']['extras']['query'] && !empty($CIDRAM['BlockInfo']['Query'])) {
        $Query = str_replace("\\", '/', strtolower(urldecode($CIDRAM['BlockInfo']['Query'])));
        $QueryNoSpace = preg_replace('/\s/', '', $Query);

        $Trigger(!$is_WP_plugin && preg_match(
            '/(?:_once|able|as(?:c|hes|sert)|c(?:hr|ode|ontents)|e(?:cho|regi|sc' .
            'ape|val)|ex(?:ec|ists)?|f(?:ile|late|unction)|get(?:c|csv|ss?)?|if|' .
            '(?<!context=edit&)include|len(?:gth)?|nt|open|p(?:ress|lace|lode|ut' .
            's)|print(?:f|_r)?|re(?:place|quire|store)|rot13|s(?:tart|ystem)|w(?' .
            ':hil|rit)e)[(\[{<$]/',
            $QueryNoSpace
        ), 'Query command injection'); // 2018.05.02 mod 2023.07.26

        $Trigger(preg_match(
            '~\$(?:globals|_(?:cookie|env|files|get|post|request|se(?:rver|ssion)))|' .
            '_contents|dotnet_load|execcgi|http_(?:cmd|sum)|move_uploaded_file|' .
            'pa(?:rse_ini_file|ssthru)|rewrite(?:cond|rule)|symlink|tmp_name|u(?:nserializ|ploadedfil)e~',
            $QueryNoSpace
        ), 'Query command injection'); // 2022.10.01

        $Trigger(preg_match('/%(?:0[0-8bcef]|1)/i', $CIDRAM['BlockInfo']['Query']), 'Non-printable characters in query'); // 2016.12.31

        $Trigger(preg_match('/(?:amp(?:;|%3b)){3,}/', $QueryNoSpace), 'Nesting attack'); // 2016.12.31 mod 2022.10.01

        $Trigger((
            !$is_WP_plugin &&
            strpos($CIDRAM['BlockInfo']['rURI'], '/ucp.php?mode=login') === false &&
            strpos($CIDRAM['BlockInfo']['rURI'], 'Category=') === false &&
            preg_match('/%(?:(25){2,}|(25)+27)/', $CIDRAM['BlockInfo']['Query'])
        ), 'Nesting attack'); // 2017.01.01 mod 2022.10.01

        $Trigger(preg_match(
            '/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/',
            $QueryNoSpace
        ), 'Query script injection'); // 2017.01.05

        $Trigger(preg_match(
            '/_(?:cookie|env|files|get|post|request|se(rver|ssion))\[/',
            $QueryNoSpace
        ), 'Query global variable hack'); // 2017.01.13

        $Trigger(strpos($QueryNoSpace, 'globals['), 'Query global variable hack'); // 2017.01.01

        $Trigger(substr($CIDRAM['BlockInfo']['Query'], -3) === '%00', 'Null truncation attempt'); // 2016.12.31
        $Trigger(substr($CIDRAM['BlockInfo']['Query'], -4) === '%000', 'Null truncation attempt'); // 2016.12.31
        $Trigger(substr($CIDRAM['BlockInfo']['Query'], -5) === '%0000', 'Null truncation attempt'); // 2016.12.31

        $Trigger(preg_match('/%(?:20\'|25[01u]|[46]1%[46]e%[46]4)/', $CIDRAM['BlockInfo']['Query']), 'Hack attempt'); // 2017.01.05
        $Trigger(preg_match('/&arrs[12]\[\]=/', $QueryNoSpace), 'Hack attempt'); // 2017.02.25
        $Trigger(preg_match('/p(?:ath|ull)\[?\]/', $QueryNoSpace), 'Hack attempt'); // 2017.01.06
        $Trigger(preg_match('/user_login,\w{4},user_(?:pass|email|activation_key)/', $QueryNoSpace), 'WP hack attempt'); // 2017.02.18
        $Trigger(preg_match('/\'%2[05]/', $CIDRAM['BlockInfo']['Query']), 'Hack attempt'); // 2017.01.05
        $Trigger(preg_match('/\|(?:include|require)/', $QueryNoSpace), 'Hack attempt'); // 2017.01.01
        $Trigger(strpos($QueryNoSpace, "'='") !== false, 'Hack attempt'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, '.php/login.php') !== false, 'Hack attempt'); // 2017.01.05
        $Trigger(preg_match('~\dhttps?:~', $QueryNoSpace), 'Hack attempt'); // 2017.01.01 mod 2018.09.22
        $Trigger(strpos($QueryNoSpace, 'id=\'') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, 'name=lobex21.php') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, 'php://') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, 'tmunblock.cgi') !== false, 'Hack attempt'); // 2017.02.18
        $Trigger(strpos($CIDRAM['BlockInfo']['Query'], '=-1%27') !== false, 'Hack attempt'); // 2017.01.05
        $Trigger(substr($QueryNoSpace, 0, 1) === ';', 'Hack attempt'); // 2017.01.05
        $Trigger(strpos($CIDRAM['BlockInfo']['Query'], 'ZWNobyBh' . 'RHJpdjQ7' . 'ZXZhbCgk' . 'X1BPU1Rb' . 'J3Z6J10pOw==') !== false, 'Hack attempt'); // 2023.08.09

        $Trigger(strpos($QueryNoSpace, 'allow_url_include=on') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'auto_prepend_file=php://input') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'cgi.force_redirect=0') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'cgi.redirect_status_env=0') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'disable_functions=""') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'open_basedir=none') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'safe_mode=off') !== false, 'Plesk hack'); // 2017.01.05
        $Trigger(strpos($QueryNoSpace, 'suhosin.simulation=on') !== false, 'Plesk hack'); // 2017.01.05

        $Trigger(preg_match('~(?:^-|/r[ks]=|dg[cd]=1|pag(?:e|ina)=-)~', $QueryNoSpace), 'Probe attempt'); // 2017.02.25
        $Trigger(preg_match('~yt=phpinfo~', $QueryNoSpace), 'Probe attempt'); // 2017.03.05

        $Trigger(preg_match(
            '/\[(?:[alrw]\]|classes|file|itemid|l(?:astrss_ap_enabled|oadfile|ocalserverfile)|pth|src)/',
            $QueryNoSpace
        ), 'Probe attempt'); // 2017.01.17 mod 2020.11.29

        $Trigger(strpos($QueryNoSpace, '+result:') !== false, 'Spam attempt'); // 2017.01.08
        $Trigger(strpos($QueryNoSpace, 'result:+\\') !== false, 'Spam attempt'); // 2017.01.08

        $Trigger(preg_match('/(?:["\'];|[;=]\|)/', $QueryNoSpace), 'Query command injection'); // 2017.01.13
        $Trigger(preg_match('/[\'"`]sysadmin[\'"`]/', $QueryNoSpace), 'Query command injection'); // 2017.02.25
        $Trigger(preg_match('/[\'"`]\+[\'"`]/', $QueryNoSpace), 'Query command injection'); // 2017.01.03
        $Trigger(preg_match('/[\'"`]\|[\'"`]/', $QueryNoSpace), 'Pipe hack'); // 2017.01.08 mod 2017.10.31 (bugged)
        $Trigger(strpos($QueryNoSpace, 'num_replies=77777') !== false, 'Overflow attempt'); // 2017.02.25
        $Trigger(strpos($CIDRAM['BlockInfo']['Query'], '++++') !== false, 'Overflow attempt'); // 2017.01.05
        $Trigger(strpos($CIDRAM['BlockInfo']['Query'], '->') !== false, 'Hack attempt'); // 2017.02.25

        $Trigger(preg_match('~src=https?:~', $QueryNoSpace), 'RFI'); // 2017.02.18 mod 2018.09.22
        $Trigger(strpos($QueryNoSpace, 'path]=') !== false, 'Path hack'); // 2017.02.18

        $Trigger(strpos($QueryNoSpace, 'e9xmkgg5h6') !== false, 'Query error'); // 2017.02.18
        $Trigger(strpos($QueryNoSpace, '5889d40edd5da7597dfc6d1357d98696') !== false, 'Query error'); // 2017.02.18

        $Trigger(preg_match('/(?:keywords|query|searchword|terms)=%d8%b3%d9%83%d8%b3/', $QueryNoSpace), 'Unauthorised'); // 2017.02.18

        $Trigger(strpos($CIDRAM['BlockInfo']['Query'], '??') !== false, 'Bad query'); // 2017.02.25
        $Trigger(strpos($CIDRAM['BlockInfo']['Query'], ',0x') !== false, 'Bad query'); // 2017.02.25
        $Trigger(strpos($CIDRAM['BlockInfo']['Query'], ',\'\',') !== false, 'Bad query'); // 2017.02.25

        $Trigger(preg_match('/id=.*(?:benchmark\(|id[xy]=|sleep\()/', $QueryNoSpace), 'Query SQLi'); // 2017.03.01
        $Trigger(preg_match(
            '~(?:from|union|where).*select|then.*else|(?:o[nr]|where).*is null|(?:inner|left|outer|right) join~',
            $QueryNoSpace
        ), 'Query SQLi'); // 2017.03.01 mod 2020.11.30

        $Trigger(preg_match('/cpis_.*i0seclab@intermal\.com/', $QueryNoSpace), 'Hack attempt'); // 2018.02.20
        $Trigger(preg_match('/^3[Xx]=3[Xx]/', $CIDRAM['BlockInfo']['Query']), 'Hack attempt'); // 2023.07.13

        /** These signatures can set extended tracking options. */
        if (
            $Trigger(strpos($QueryNoSpace, '$_' . '[$' . '__') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(strpos($QueryNoSpace, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(strpos($Query, 'rm ' . '-rf') !== false, 'Hack attempt') || // 2017.01.02
            $Trigger(strpos($QueryNoSpace, ';c' . 'hmod7' . '77') !== false, 'Hack attempt') || // 2017.01.05
            $Trigger(substr($QueryNoSpace, 0, 2) === '()', 'Bash/Shellshock') || // 2017.01.05
            $Trigger(strpos($QueryNoSpace, '0x31303235343830303536') !== false, 'Probe attempt') || // 2017.02.25
            $Trigger(preg_match('~(?:modez|osc|tasya)=|=(?:(?:bot|scanner|shell)z|psybnc)~', $QueryNoSpace), 'Query command injection') // 2017.02.25 mod 2021.06.28
        ) {
            $CIDRAM['Tracking options override'] = 'extended';
        }
    }

    /** If enabled, fetch the first 1MB of raw input from the input stream. */
    if ($CIDRAM['Config']['extras']['raw']) {
        $Handle = fopen('php://input', 'rb');
        $RawInput = fread($Handle, 1048576);
        fclose($Handle);
    }

    /**
     * Signatures based on raw input start from here.
     * Please report all false positives to https://github.com/CIDRAM/CIDRAM/issues
     */
    if ($CIDRAM['Config']['extras']['raw'] && $RawInput) {
        $RawInputSafe = strtolower(preg_replace('/[\s\x00-\x1f\x7f-\xff]/', '', $RawInput));

        $Trigger(preg_match('/charcode\(88,83,83\)/', $RawInputSafe), 'Hack attempt'); // 2017.03.01
        $Trigger((
            strpos($RawInputSafe, '<?xml') !== false &&
            strpos($RawInputSafe, '<!doctype') !== false &&
            strpos($RawInputSafe, '<!entity') !== false
        ), 'Suspicious request'); // 2018.07.10
        $Trigger(strpos($RawInputSafe, 'inputbody:action=update&mfbfw') !== false, 'FancyBox exploit attempt'); // 2017.03.01

        $Trigger(!$is_WP_plugin && preg_match(
            '~(?:lwp-download|fetch)ftp://|(?:fetch|lwp-download|wget)https?://|<name|method(?:call|name)|value>~i',
            $RawInputSafe
        ), 'POST RFI'); // 2018.07.10

        /** Joomla plugins update bypass (POST RFI conflict). */
        $Bypass(
            ($CIDRAM['BlockInfo']['SignatureCount'] - $Before) > 0 &&
            strpos($CIDRAM['BlockInfo']['rURI'], 'administrator/') !== false &&
            strpos($CIDRAM['BlockInfo']['WhyReason'], 'POST RFI') !== false,
            'Joomla plugins update bypass (POST RFI conflict)'
        ); // 2017.05.10

        $Trigger(preg_match(
            '~(?:%61%(6c%6c%6f%77%5f%75%72%6c%5f%69%6e%63%6c%75%64%65%3d%6f%6e|7' .
            '5%74%6f%5f%70%72%65%70%65%6e%64%5f%66%69%6c%65%3d%70%68%70%3a%2f%2f' .
            '%69%6e%70%75%74)|%63%67%69%2e%(66%6f%72%63%65%5f%72%65%64%69%72%65%' .
            '63%74%3d%30|72%65%64%69%72%65%63%74%5f%73%74%61%74%75%73%5f%65%6e%7' .
            '6%3d%30)|%64%69%73%61%62%6c%65%5f%66%75%6e%63%74%69%6f%6e%73%3d%22%' .
            '22|%6f%70%65%6e%5f%62%61%73%65%64%69%72%3d%6e%6f%6e%65|%73%(61%66%6' .
            '5%5f%6d%6f%64%65%3d%6f%66%66|75%68%6f%73%69%6e%2e%73%69%6d%75%6c%61' .
            '%74%69%6f%6e%3d%6f%6e))~',
            $RawInputSafe
        ), 'Plesk hack'); // 2017.03.01

        $Trigger(preg_match('~(?:6\D*1\D*6\D*6\D*9\D*4\D*7\D*8\D*5)~i', $RawInput), 'Spam attempt'); // 2017.03.01
        $Trigger(preg_match('~//dail' . 'ydigita' . 'ldeals' . '\.info/~i', $RawInput), 'Spam attempt'); // 2017.03.01

        $Trigger(preg_match(
            '~C[46][iy]1F[12]EA7217PB(?:DF|TL)[15]FlcH(?:77|98)s[0O]pf[0O](?:%2f' .
            '|.)[Sr]1[Zt](?:15|76)(?:%2f|.)(?:13ga|OKFae)~',
            $RawInput
        ), 'Compromised API key used in brute-force attacks'); // 2020.08.08

        $Trigger(preg_match('~streaming\.live365\.com/~i', $RawInput), 'Spamvertised domain'); // 2020.03.02

        /** These signatures can set extended tracking options. */
        if (
            $Trigger(preg_match('~/â\\x80¦x\.php~i', $RawInput), 'Probe attempt') || // 2017.03.01
            $Trigger(preg_match('~\([\'"](?:zwnobyai|awyoznvu)~', $RawInputSafe), 'Injection attempt') || // 2017.03.01
            $Trigger(preg_match('~^/\?-~', $RawInput), 'Hack attempt') || // 2017.03.01
            $Trigger(strpos($RawInputSafe, '$_' . '[$' . '__') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(strpos($RawInputSafe, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt') || // 2017.03.01
            $Trigger(preg_match('~&author_name=(?:%5b|\[)~', $RawInputSafe), 'Bot detection') // 2017.03.01
        ) {
            $CIDRAM['Tracking options override'] = 'extended';
        }
    }

    /** Reporting. */
    if (!empty($CIDRAM['BlockInfo']['IPAddr'])) {
        if (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Compromised API key') !== false) {
            $CIDRAM['Reporter']->report([15], ['Unauthorised use of known compromised API key detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'FancyBox exploit attempt') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['FancyBox hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Hack attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Nesting attack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Nesting attack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Null truncation attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Null truncation attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Overflow attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Overflow attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Path hack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Path hack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Pipe hack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Pipe hack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Plesk hack') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['Plesk hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Probe attempt') !== false) {
            $CIDRAM['Reporter']->report([19], ['Probe detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query SQLi') !== false) {
            $CIDRAM['Reporter']->report([16], ['SQL injection attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query command injection') !== false) {
            $CIDRAM['Reporter']->report([15], ['Query command injection attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query global variable hack') !== false) {
            $CIDRAM['Reporter']->report([15], ['Query global variable hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Query script injection') !== false) {
            $CIDRAM['Reporter']->report([15], ['Query script injection attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'POST RFI') !== false) {
            $CIDRAM['Reporter']->report([15], ['POST RFI detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Shell upload attempt') !== false) {
            $CIDRAM['Reporter']->report([15], ['Shell upload attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Spam attempt') !== false) {
            $CIDRAM['Reporter']->report([10], ['Detected a spambot attempting to drop its payload.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Spam attempt') !== false) {
            $CIDRAM['Reporter']->report([10, 19], ['Detected a spambot attempting to drop its payload.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'WP hack attempt') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['WordPress hack attempt detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        } elseif (strpos($CIDRAM['BlockInfo']['WhyReason'], 'Traversal attack') !== false) {
            $CIDRAM['Reporter']->report([15, 21], ['Traversal attack detected.'], $CIDRAM['BlockInfo']['IPAddr']);
        }
    }
};

/** Execute closure. */
$CIDRAM['ModuleResCache'][$Module]();
