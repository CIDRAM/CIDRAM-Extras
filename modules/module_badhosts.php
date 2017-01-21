<?php
/**
 * This file is a part of the CIDRAM package, and can be downloaded for free
 * from {@link https://github.com/Maikuolan/CIDRAM/ GitHub}.
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: Bad hosts module (last modified: 2017.01.21).
 *
 * Many thanks to Michael Hopkins, the creator of ZB Block (GNU/GPLv2), and to
 * the community behind it (Spambot Security) for inspiring/developing many of
 * the signatures contained within this module.
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
$InstaBan = array('Options' => array('TrackTime' => 31536000, 'TrackCount' => 1000));

/** Fetch hostname. */
if (empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse-IPv4']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Signatures start here. */
if ($CIDRAM['Hostname'] && $CIDRAM['Hostname'] !== $CIDRAM['BlockInfo']['IPAddr']) {
    $HN = preg_replace('/\s/', '', str_replace("\\", '/', strtolower(urldecode($CIDRAM['Hostname']))));

    $Trigger(substr($HN, 0, 2) === '()', 'Bash/Shellshock', '', $InstaBan); // 2017.01.21

    $Trigger(preg_match(
        '/(?:0wn[3e]d|:(\{[a-z]:|[a-z0-9][;:]\})|h[4a]c' . 'k(?:e[dr]|ing|t(' .
        '[3e][4a]m|[0o]{2}l))|%(0[0-8bcef]|1)|[`\'"])/',
    $HN), 'Banned hostname', '', $InstaBan); // 2017.01.21
    $Trigger(strpos($CIDRAM['Hostname'], 'rm ' . '-rf') !== false, 'Banned hostname', '', $InstaBan); // 2017.01.21
    $Trigger(strpos($HN, 'sh' . 'el' . 'l_' . 'ex' . 'ec') !== false, 'Banned hostname', '', $InstaBan); // 2017.01.21

    $Trigger(strpos($HN, '$_' . '[$' . '__') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.21
    $Trigger(strpos($HN, '@$' . '_[' . ']=' . '@!' . '+_') !== false, 'Shell upload attempt', '', $InstaBan); // 2017.01.21

    $Trigger(preg_match(
        '/\$(?:globals|_(cookie|env|files|get|post|request|se(rver|ssion)))/',
    $HN), 'Command injection'); // 2017.01.21

    $Trigger(preg_match(
        '/(?:<(\?|body|i?frame|object|script)|(body|i?frame|object|script)>)/',
    $HN), 'Script injection'); // 2017.01.21

    $Trigger(preg_match('/(?:captch|dbcapi\.me)/', $HN), 'CAPTCHA cracker host'); // 2017.01.21

    $Trigger(preg_match(
        '/(?:(barefruit|detangled|kimsufi|lightspeedsystems|netcomber|page-s' .
        'tore|\.(giga-dns|pointandchange|solidseo(dedicated|vps)|vadino))\.c' .
        'om$|poneytelecom\.eu$|buyurl\.net$|seomoz\.org$|itrack\.ru$|(2kom|s' .
        'olomono)\.ru|awcheck|b(oardreader|reakingtopics|uysellsales)|c(eptr' .
        'o|heapseovps|yber-uslugi)|jackwellsmusic|s(mileweb\.com\.ua|quider|' .
        'tartdedicated\.)|(exa|we|youdao)bot)/',
    $HN), 'SEO/Bothost/Scraper/Spamhost'); // 2017.01.21
    $Trigger(preg_match(
        '/(?:prking\.com\.au$|(2dayhost|inkjetrefillink)\.com|(23gb|35up|acc' .
        'elovation|bestprice|mantraonline|onlinehome-server\.myforexvps)\.co' .
        'm$|mobilemarketingaid\.info|(4u|onlinehome-server)\.info$|(3fn|drag' .
        'onara|onlinehome-server)\.net$|drugstore|l(iwio\.|uxuryhandbag))/',
    $HN), 'Spamhost'); // 2017.01.21
    $Trigger(preg_match(
        '/(?:rumer|pymep|румер)/',
    $HN), 'Spamhost', '', $InstaBan); // 2017.01.21

    $Trigger(preg_match(
        '/(?:^test\.|anahaqq|core\.youtu\.me|hosted-(by|in)|no-(data|(revers' .
        'e-)?r?dns)|qeas|spletnahisa|therewill\.be|unassigned|work\.from)/',
    $HN), 'Questionable Host'); // 2017.01.21

    $Trigger(empty($CIDRAM['Ignore']['Kyivstar']) && strpos($HN, 'kyivstar') !== false, 'Kyivstar'); // 2017.01.21 (ASNs 12530, 15895, 35081)
    $Trigger(empty($CIDRAM['Ignore']['Seznam.cz']) && strpos($HN, 'seznam.cz') !== false, 'Seznam.cz'); // 2017.01.21 (ASNs 43037, 200600)
    $Trigger(empty($CIDRAM['Ignore']['SISTRIX GmbH']) && strpos($HN, 'sistrix') !== false, 'SISTRIX GmbH'); // 2017.01.21 (no ASN)
    $Trigger(empty($CIDRAM['Ignore']['XEEX']) && strpos($HN, 'xeex') !== false, 'XEEX'); // 2017.01.21 (ASN 27524)

    $Trigger(preg_match(
        '/(?:(akpackaging|shared-server|jkserv)\.net|(academicedge|aramenet|' .
        'dailyrazor|dinaserver|ibuzytravel|phishmongers|server306|web(factio' .
        'n|hostinghub|sitewelcome)|\.siteprotect)\.com|(acetrophies|\.pomser' .
        've2)\.co\.uk|webhostserver\.biz|\.haremo\.de|webcreators\.nl|rockwe' .
        'llmuseum\.org|skyware\.pl|(timeweb|vpsnow)\.ru)/',
    $HN), 'Probe/Scanner'); // 2017.01.21

    $Trigger(preg_match('/(?:thefreevpn|vpn(999\.com|gate))/', $HN), 'Risky/Proxy/VPN Host'); // 2017.01.21

    $Trigger(preg_match(
        '/(?:(dimenoc|internetserviceteam|ipredat(e|or)|webandnetworksolutio' .
        'ns|xcelmg)\.com|hostnoc\.net|is74\.ru)$/',
    $HN), 'Dangerous Host'); // 2017.01.21

    $Trigger(preg_match(
        '/(?:\.appian|\.bc\.googleusercontent|\.c(loud|tera)|\.dyn|\.emc|\.f' .
        'orce|\.gnip|\.gridlayer|\.hosting|\.icims|\.pa(norama|rallels)|\.qu' .
        'est|\.thegridlayer|\.v(oda|ultr)|\.workday|10gen|12designer|3leafsy' .
        'stems|3tera|a(conex|dvologix|gathon|ltornetworks|mitive|pp(irio|ist' .
        'ry|jet|nexus|renda|zero)|ptana|r(iasystems|juna|tofdefence)|sterdat' .
        'a|syanka|zati)|b(eam4d|hivesoft|irtondemand|linklogic|lue(lock|wolf' .
        ')|oomi|ucketexplorer|ungeeconnect)|c(a(msolutionsinc|s(pio|satt|tir' .
        'on))|l(arioanalytics|ickability|oud(42|9analytics|computingchina|co' .
        'ntrol|era|foundry|kick|scale|status|switch|works)|usterseven)|o(ghe' .
        'ad|hesiveft|ldlightsolutions|ncur|ntroltier))|d(ata(line|sisar|syna' .
        'ps)|irectlaw|oclanding|ropbox|ynamsoft)|e(last(ichosts|ra)|n(gineya' .
        'rd|omalism|stratus)|telos|ucalyptus|vapt|vionet)|f(athomdb|lexiscal' .
        'e)|g(emstone|igaspaces|ogrid)|h(eroku|exagrid|ubspan|yperic)|i(clou' .
        'd|modrive|nfo(bright|rmatica)|tricityhosting)|j(oyent|umpbox|ungleb' .
        'ox)|k(2analytics|aavo|eynote|nowledgetree)|l(ayeredtech|iveops|oads' .
        'torm|ogixml|ongjump|tdomains)|m(o(derro|rphexchange|sso|zy)|turk|ul' .
        'esoft)|n(asstar|e(t(app|documents|suite)|wrelic|wservers)|ionex|irv' .
        'anix|ovatium|scaled)|o(co-inc|nelogin|npathtech|penqrm|psource)|p(a' .
        'ra(scal|tur)e|inqidentity|ivotlink|luraprocessing)|q(layer|rimp|uan' .
        'ti(vo|x-uk))|r(ackspace(cloud)?|e(di2|ductivelabs|liacloud|sponsys)' .
        '|ight(now|scale)|ollbase|path)|s(alesforce|avvis|ertifi|kytap|naplo' .
        'gic|oasta|pringcm|tax|treetsmarts|uccessmetrics|ymplified|yncplicit' .
        'y)|t(aleo|err[ae]mark|h(eprocessfactory|inkgos|oughtexpress)|rustsa' .
        'as)|utilitystatus|v(aultscape|ertica|mware|ordel)|web(hosting\.uk|s' .
        'calesolutions)|x(actlycorp|ythos)|z(embly|imory|manda|oho|uora))\.c' .
        'om$/',
    $HN), 'Cloud Service'); // 2017.01.21

    $Trigger(preg_match(
        '/(?:\.box|\.voxel|1978th|collab|enkiconsulting)\.net$/',
    $HN), 'Cloud Service'); // 2017.01.21

    $Trigger(preg_match('/zetta\.net$/', $HN) && !preg_match('/ssg-corp\.zetta\.net$/', $HN), 'Cloud Service'); // 2017.01.21

    $Trigger(preg_match(
        '/(?:candycloud\.eu|(\.terracotta|beowulf|iboss|memcached|opennebula' .
        '|xen)\.org|andersdenken\.at|eucalyptus\.cs\.uscb\.edu|g\.ho\.st|mor' .
        '\.ph|optimal\.de|xcalibre\.co\.uk)$/',
    $HN), 'Cloud Service'); // 2017.01.21

    $Trigger(preg_match('/(?:cloudsigma|ipxserver|linode)/', $HN), 'Cloud Service'); // 2017.01.21

    $Trigger(empty($CIDRAM['Ignore']['SoftLayer']) && preg_match('/softlayer\.com$/', $HN) && (
        !substr_count($CIDRAM['BlockInfo']['UALC'], 'showyoubot') &&
        !substr_count($CIDRAM['BlockInfo']['UALC'], 'disqus') &&
        !substr_count($CIDRAM['BlockInfo']['UA'], 'Feedspot http://www.feedspot.com') &&
        !substr_count($CIDRAM['BlockInfo']['UA'], 'Superfeedr bot/2.0') &&
        !substr_count($CIDRAM['BlockInfo']['UA'], 'Feedbot')
    ), 'SoftLayer'); // 2017.01.21 (ASN 36351)

}
