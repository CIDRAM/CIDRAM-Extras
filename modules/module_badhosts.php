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
 * This file: Bad hosts blocker module (last modified: 2017.02.25).
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

/** Inherit trigger closure (see functions.php). */
$Bypass = $CIDRAM['Bypass'];

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
$InstaBan = array('Options' => array('TrackTime' => 31536000, 'TrackCount' => 1000));

/** Fetch hostname. */
if (empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse-IPv4']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Signatures start here. */
if ($CIDRAM['Hostname'] && $CIDRAM['Hostname'] !== $CIDRAM['BlockInfo']['IPAddr']) {
    $HN = preg_replace('/\s/', '', str_replace("\\", '/', strtolower(urldecode($CIDRAM['Hostname']))));
    $UA = str_replace("\\", '/', strtolower(urldecode($CIDRAM['BlockInfo']['UA'])));
    $UANoSpace = preg_replace('/\s/', '', $UA);

    $Trigger(substr($HN, 0, 2) === '()', 'Bash/Shellshock', '', $InstaBan); // 2017.01.21

    $Trigger(preg_match(
        '/(?:0wn[3e]d|:(\{[a-z]:|[a-z0-9][;:]\})|h[4a]ck(e[dr]|ing|[7t]([3e]' .
        '[4a]m|[0o]{2}l))|%(0[0-8bcef]|1)|[`\'"]|^[-.:]|[-.:]$|[.:][a-z\d-]{' .
        '64,}[.:])/',
    $HN), 'Banned hostname', '', $InstaBan); // 2017.02.14

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
        '/(?:(qvt|telsp)\.net\.br$|(\.(giga-dns|oodle|pointandchange|solidse' .
        'o(dedicated|vps)?|topsy|vadino)|barefruit|colo\.iinet|detangled|kim' .
        'sufi|lightspeedsystems|netcomber|page-store|setooz|technicolor)\.co' .
        'm$|poneytelecom\.eu$|\.cnr\.it$|kiyosho\.jp$|(\.pldt|buyurl|isnet|m' .
        'fnx)\.net$|seomoz\.org$|\.rdsnet\.ro$|(itrack|rulinki)\.ru$|(2kom|s' .
        'olomono)\.ru|\.v4\.ngi\.it|awcheck|b(oardreader|reakingtopics|uysel' .
        'lsales)|c(eptro|heapseovps|yber-uslugi)|jackwellsmusic|s(emalt|mile' .
        'web\.com\.ua|quider|tartdedicated\.)|(exa|fulltextro|we|you?dao)bot' .
        ')/',
    $HN), 'SEO/Bothost/Scraper/Spamhost'); // 2017.02.16

    $Trigger(preg_match(
        '/(?:prking\.com\.au$|(23gb|35up|accelovation|bestprice|mantraonline' .
        '|onlinehome-server\.myforexvps)\.com$|(2dayhost|inkjetrefillink)\.c' .
        'om|(4u|onlinehome-server)\.info$|mobilemarketingaid\.info|(3fn|drag' .
        'onara|onlinehome-server|pool\.ukrtel)\.net$|mail\.ru$|fibersunucu\.' .
        'com\.tr|drugstore|l(iwio\.|uxuryhandbag))/',
    $HN), 'Spamhost'); // 2017.02.09

    $Trigger(preg_match(
        '/(?:rumer|pymep|румер)/',
    $HN), 'Spamhost', '', $InstaBan); // 2017.01.21

    $Trigger(preg_match('/(?:cjh-law\.com$)/', $HN), 'Phisher / Phishing Host'); // 2017.02.14

    $Trigger(preg_match('/(?:exatt\.net$|unpef\.org$)/', $HN), 'Pornobot/Pornhost'); // 2017.02.16

    $Trigger(preg_match(
        '/(?:^(damage|moon|test)\.|anahaqq|core\.youtu\.me|hosted-(by|in)|no' .
        '-(data|(reverse-)?r?dns)|qeas|spletnahisa|therewill\.be|unassigned|' .
        'work\.from|yhost\.name)/',
    $HN), 'Questionable Host'); // 2017.01.30

    $Trigger(preg_match(
        '/(?:\.(as13448|websense)\.|(bibbly|pulsepoint|zvelo)\.com|\.filespo' .
        't\.com$|westdc\.net|propagation\.net$|m(ajestic|eanpath)|tag-trek)/',
    $HN), 'Unauthorised'); // 2017.02.09

    $Trigger(preg_match(
        '/(?:anchorfree|hotspotsheild|esonicspider\.com$)/',
    $HN), 'Hostile/esonicspider'); // 2017.02.06

    $Trigger(preg_match(
        '/(?:megacom\.biz$|ideastack\.com$|dotnetdotcom\.org$|controlyourself\.online|seeweb\.it)/',
    $HN), 'Hostile/Unauthorised'); // 2017.02.14

    $Trigger(preg_match(
        '/(?:brandaffinity)/',
    $HN), 'Hostile/SLAPP'); // 2017.02.06

    $Trigger(preg_match(
        '/(?:andersdenken\.at$|i(g|nsite)\.com\.br$|terra\.cl$|(\.(appian|bc' .
        '\.googleusercontent|c(loud|tera)|dyn|emc|f(orce|sfreeware)|g(nip|ri' .
        'dlayer)|hosting|icims|pa(norama|rallels)|quest|thegridlayer|v(oda|u' .
        'ltr)|w(ebzilla|orkday))|10gen|12designer|3leafsystems|3tera|a(ccent' .
        'rainc|conex|dvologix|gathon|ltornetworks|mericanforeclosures|mitive' .
        '|pp(irio|istry|jet|nexus|renda|spot|zero)|ptana|r(iasystems|juna|to' .
        'fdefence)|sterdata|syanka|uthenticnetworks|zati)|b(alticservers|eam' .
        '4d|hivesoft|irtondemand|linklogic|lue(host|lock|wolf)|oomi|ucketexp' .
        'lorer|ungeeconnect)|c(a(dinor|msolutionsinc|s(pio|satt|tiron))|l(ar' .
        'ioanalytics|ickability|oud(42|9analytics|computingchina|control|era' .
        '|foundry|kick|scale|status|switch|works)|usterseven)|o(ghead|hesive' .
        'ft|ldlightsolutions|ncur|ntroltier)|tinets)|d(ata(line|sisar|synaps' .
        ')|edicatedpanel|irectlaw|ns-safe|oclanding|ropbox|ynamsoft)|e(last(' .
        'ichosts|ra)|n(gineyard|omalism|stratus)|telos|ucalyptus|vapt|vionet' .
        ')|f(athomdb|lexiscale|ollowmeoffice)|g(emstone|igaspaces|ogrid|roup' .
        'cross)|h(eroku|exagrid|olhost|ost(acy|cats|ing24)|ubspan|yperic)|i(' .
        'cloud|modrive|nfo(bright|rmatica)|tricityhosting)|j(oyent|u(mpbox|n' .
        'glebox|sthost))|k(2analytics|aavo|eynote|nowledgetree)|l(ayeredtech' .
        '|inkneo|iveops|oadstorm|ogixml|ongjump|tdomains)|m(o(derro|jsite|rp' .
        'hexchange|sso|zy)|idphase|turk|ulesoft)|n(asstar|e(ointeractiva|t(a' .
        'pp|documents|suite|topia)|wrelic|wservers)|ionex|irvanix|ovatium|sc' .
        'aled)|o(co-inc|nelogin|npathtech|penqrm|psource)|p(ara(scal|tur)e|h' .
        'atservers|i(emontetv|nqidentity|votlink)|luraprocessing)|q(layer|ri' .
        'mp|uanti(vo|x-uk))|r(ackspace(cloud)?|e(di2|ductivelabs|lia(blehost' .
        'ing|cloud)|sponsys)|ight(now|scale)|ollbase|omania-webhosting|path)' .
        '|s(alesforce|avvis|ertifi|kytap|martservercontrol|naplogic|oasta|pr' .
        'ingcm|tax|treetsmarts|uccessmetrics|wifttrim|ymplified|yncplicity)|' .
        't(aleo|err[ae]mark|h(eprocessfactory|inkgos|oughtexpress)|rustsaas)' .
        '|utilitystatus|v(aultscape|ertica|mware|ordel)|web(hosting\.uk|scal' .
        'esolutions)|x(actlycorp|lhost|ythos)|z(embly|imory|manda|oho|uora))' .
        '\.com$|(artisticgoals|host(gator|ingprod)|instantdedicated|khavarza' .
        'min|missiondish|newslettersrus|profninja|se(curityspace|rve(path|rb' .
        'uddies))|viral-customers)\.com|((\.|kunden)server|clanmoi|fastwebse' .
        'rver|optimal|server4you)\.de$|your-server\.de|eucalyptus\.cs\.uscb' .
        '\.edu$|candycloud\.eu$|adsinmedia\.co\.in$|server\.lu$|iam\.net\.ma' .
        '$|starnet\.md$|(\.(bhsrv|box|propagation|voxel)|1978th|collab|enkic' .
        'onsulting|host\.caracastelecom)\.net$|re(liablesite|plyingst)\.net|' .
        'hitech-hosting\.nl|(\.terracotta|beowulf|iboss|memcached|opennebula' .
        '|xen)\.org$|mor\.ph$|(ogicom|vampire)\.pl$|(cyber-host|slaskdatacen' .
        'ter)\.pl|rivreg\.ru$|(tkvprok|vympelstroy)\.ru|g\.ho\.st$|(webfusio' .
        'n|xcalibre)\.co\.uk$|bergdorf-group|cloudsigma|dreamhost|ipxserver|' .
        'linode|money(mattersnow|tech\.mg)|productsnetworksx|psychz|scopehos' .
        'ts|s(p?lice|teep)host)/',
    $HN), 'Cloud Service / Server Farm'); // 2017.02.14

    $Trigger(empty($CIDRAM['Ignore']['Agava Ltd']) && preg_match('/agava\.net$/', $HN), 'Agava Ltd'); // 2017.02.06 (ASN 43146)
    $Trigger(empty($CIDRAM['Ignore']['AltusHost B.V']) && preg_match('/altushost\.com$/', $HN), 'AltusHost B.V'); // 2017.02.09 (ASN 51430)
    $Trigger(empty($CIDRAM['Ignore']['Bezeq International']) && preg_match('/bezeqint\.net$/', $HN), 'Bezeq International'); // 2017.02.09 (ASN 8551)
    $Trigger(empty($CIDRAM['Ignore']['Bharti Airtel']) && preg_match('/\.airtelbroadband\.in$/', $HN), 'Bharti Airtel'); // 2017.02.06 (ASNs 9498, 24560, 45514, 45609)
    $Trigger(empty($CIDRAM['Ignore']['ColoCrossing']) && strpos($HN, 'colocrossing.com') !== false, 'ColoCrossing'); // 2017.01.30 (ASN 36352)
    $Trigger(empty($CIDRAM['Ignore']['GorillaServers, Inc']) && strpos($HN, 'gorillaservers') !== false, 'GorillaServers, Inc'); // 2017.02.06 (ASN 53850)
    $Trigger(empty($CIDRAM['Ignore']['Host Europe GmbH']) && strpos($HN, 'hosteurope') !== false, 'Host Europe GmbH'); // 2017.01.30 (numerous ASNs)
    $Trigger(empty($CIDRAM['Ignore']['HOSTKEY B.V']) && preg_match('/hostkey\.ru$/', $HN), 'HOSTKEY B.V'); // 2017.02.15 (ASN 57043)
    $Trigger(empty($CIDRAM['Ignore']['Kyivstar']) && strpos($HN, 'kyivstar') !== false, 'Kyivstar'); // 2017.01.21 (ASNs 12530, 15895, 35081)
    $Trigger(empty($CIDRAM['Ignore']['Leaseweb']) && strpos($HN, 'leaseweb') !== false, 'Leaseweb'); // 2017.02.06 (numerous ASNs)
    $Trigger(empty($CIDRAM['Ignore']['Nobis/Ubiquity']) && preg_match('/(?:nobis|ubiquity)/', $HN), 'Nobis/Ubiquity'); // 2017.02.15 (ASN 15003)
    $Trigger(empty($CIDRAM['Ignore']['QuadraNet, Inc']) && preg_match('/quadranet\.com$/', $HN), 'QuadraNet, Inc'); // 2017.02.14 (ASNs 8100, 29761, 62639)
    $Trigger(empty($CIDRAM['Ignore']['Seznam.cz']) && strpos($HN, 'seznam.cz') !== false, 'Seznam.cz'); // 2017.01.21 (ASNs 43037, 200600)
    $Trigger(empty($CIDRAM['Ignore']['SISTRIX GmbH']) && strpos($HN, 'sistrix') !== false, 'SISTRIX GmbH'); // 2017.01.21 (no ASN)
    $Trigger(empty($CIDRAM['Ignore']['Versaweb, LLC']) && strpos($HN, 'versaweb') !== false, 'Versaweb, LLC'); // 2017.02.14 (ASN 36114)
    $Trigger(empty($CIDRAM['Ignore']['Voxility LLC']) && strpos($HN, 'voxility.net') !== false, 'Voxility LLC'); // 2017.02.06 (ASN 3223)
    $Trigger(empty($CIDRAM['Ignore']['XEEX']) && strpos($HN, 'xeex') !== false, 'XEEX'); // 2017.01.21 (ASN 27524)

    $Trigger(preg_match(
        '/(?:(\.above|shared-server|jkserv)\.net$|akpackaging\.net|(academic' .
        'edge|dailyrazor|ibuzytravel|server306|webfaction|\.siteprotect)\.co' .
        'm$|(aramenet|dinaserver|phishmongers|web(hostinghub|sitewelcome))\.' .
        'com|acetrophies\.co\.uk$|\.pomserve2\.co\.uk|webhostserver\.biz$|\.' .
        'haremo\.de$|webcreators\.nl|rockwellmuseum\.org|skyware\.pl$|vpsnow' .
        '\.ru$|timeweb\.ru)/',
    $HN), 'Probe/Scanner'); // 2017.02.14

    $Trigger(preg_match(
        '/(?:(\.oroxy|anonine)\.com$|thefreevpn|vpn(999\.com|gate)|public-net)/',
    $HN), 'Risky/Proxy/VPN Host'); // 2017.02.09

    $Trigger(preg_match(
        '/(?:(dimenoc|dumpyourbitch|hostenko|internetserviceteam|ipredat(e|o' .
        'r)|krypt|webandnetworksolutions|xcelmg)\.com|mbox\.kz|chello\.pl|do' .
        'ctore\.sk|hostnoc\.net|(\.host|ertelecom|is74)\.ru)$/',
    $HN), 'Dangerous Host'); // 2017.02.14

    $Trigger(preg_match(
        '/(?:(iweb|privatedns)\.com$|iweb\.ca$|^(www\.)?iweb)/',
    $HN), 'Domain Snipers'); // 2017.02.15

    $Trigger(preg_match(
        '/(?:45ru\.net\.au|dedipower|p(rohibitivestuff|wn)|triolan)/',
    $HN), 'Dangerous Host'); // 2017.02.14

    $Trigger(preg_match('/zetta\.net$/', $HN) && !preg_match('/ssg-corp\.zetta\.net$/', $HN), 'Cloud Service / Server Farm'); // 2017.02.14
    $Trigger(preg_match('/veloxzone\.com\.br$/', $HN) && !preg_match('/\.user\.veloxzone\.com\.br$/', $HN), 'Cloud Service / Server Farm'); // 2017.02.14

    $Trigger(empty($CIDRAM['Ignore']['SoftLayer']) && preg_match('/softlayer\.com$/', $HN) && (
        !substr_count($CIDRAM['BlockInfo']['UALC'], 'showyoubot') &&
        !substr_count($CIDRAM['BlockInfo']['UALC'], 'disqus') &&
        !substr_count($CIDRAM['BlockInfo']['UA'], 'Feedspot http://www.feedspot.com') &&
        !substr_count($CIDRAM['BlockInfo']['UA'], 'Superfeedr bot/2.0') &&
        !substr_count($CIDRAM['BlockInfo']['UA'], 'Feedbot')
    ), 'SoftLayer'); // 2017.01.21 (ASN 36351)

    $Trigger(preg_match(
        '/(?:(starlogic|temka)\.biz$|ethymos\.com\.br$|(amplilogic|astranigh' .
        't|borderfreehosting|creatoor|dl-hosting|hosting-ie|idknet|ipilum|ku' .
        'zbass|prommorpg|uxxicom|vdswin|x-svr)\.com$|(ahost01|efdns|em-zwo|h' .
        'aebdler-treff|key(account|mars64)|mail\.adc|rootbash|securewebserve' .
        'r|tagdance|traders-briefing|vilitas|w-4)\.de$|(hostrov|kemhost|neto' .
        'rn|power-web34|profithost|volia)\.net$|cssgroup\.lv|(nasza-klasa|so' .
        'ftel\.com)\.pl$|(corbina|cpms|datapoint|elsv-v|hc|itns|limt|majordo' .
        'mo|mtu-net|netorn|nigma|relan|spb|totalstat)\.ru|((cosmonova|sovam|' .
        'utel)\.net|odessa|poltava|rbn\.com|volia)\.ua$|aceleo|dedibox|filme' .
        'fashion|infobox|key(machine|server|web)|kyklo|laycat|oliro)/',
    $HN), 'RBN'); // 2017.02.06

    $Trigger(preg_match('/amazonaws\.com$/', $HN) && (
        !preg_match(
            '/(?:alexa|postrank|twitt(urly|erfeed)|bitlybot|unwindfetchor|me' .
            'tauri|pinterest|silk-accelerated=true$)/',
        $UANoSpace) &&
        substr($CIDRAM['BlockInfo']['UA'], -17) !== 'Digg Feed Fetcher' &&
        substr($CIDRAM['BlockInfo']['UA'], -32) !== 'Feedspot http://www.feedspot.com' &&
        substr($CIDRAM['BlockInfo']['UA'], 0, 18) !== 'NewRelicPinger/1.0' && !(
            strpos($CIDRAM['BlockInfo']['UA'], '; KF') !== false &&
            strpos($CIDRAM['BlockInfo']['UA'], 'Silk/') !== false &&
            strpos($CIDRAM['BlockInfo']['UA'], 'like Chrome/') !== false
        )
    ), 'Amazon Web Services'); // 2017.02.14

    $Trigger((
        empty($CIDRAM['Ignore']['OVH Systems']) &&
        preg_match('/ovh\.net$/', $HN) &&
        strpos($UANoSpace, 'paperlibot') === false
    ), 'OVH Systems'); // 2017.02.16

    $Trigger(preg_match('/^localhost$/', $HN) && (
        !preg_match('/^(?:1(27|92\.168)(\.1?[0-9]{1,2}|\.2[0-4][0-9]|\.25[0-5]){2,3}|\:\:1)$/', $CIDRAM['BlockInfo']['IPAddr'])
    ), 'Spoofed/Fake Hostname', '', $InstaBan); // 2017.02.25
    $Trigger(preg_match('/\.local$/', $HN), 'Spoofed/Fake Hostname'); // 2017.02.06

    $Trigger($HN === '.', 'DNS error', '', $InstaBan); // 2017.02.25

}

/** WordPress cronjob bypass. */
$Bypass(
    (($CIDRAM['BlockInfo']['SignatureCount'] - $Infractions) > 0) &&
    preg_match('~^/wp-cron\.php\?doing_wp_cron=[0-9]+\.[0-9]+$~', $_SERVER['REQUEST_URI']) &&
    defined('DOING_CRON'),
'WordPress cronjob bypass');
