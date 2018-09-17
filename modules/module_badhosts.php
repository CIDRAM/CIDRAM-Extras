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
 * This file: Bad hosts blocker module (last modified: 2018.09.17).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Inherit trigger closure (see functions.php). */
$Trigger = $CIDRAM['Trigger'];

/** Inherit bypass closure (see functions.php). */
$Bypass = $CIDRAM['Bypass'];

/** Options for instantly banning (sets tracking time to 1 year and infraction count to 1000). */
$InstaBan = ['Options' => ['TrackTime' => 31536000, 'TrackCount' => 1000]];

/** Fetch hostname. */
if (empty($CIDRAM['Hostname'])) {
    $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
}

/** Safety mechanism against false positives caused by failed lookups. */
if ($CIDRAM['Hostname'] === 'b.in-addr-servers.nstldianaorgxHp:') {
    $DoNotContinue = true;
}

/** Signatures start here. */
if ($CIDRAM['Hostname'] && $CIDRAM['Hostname'] !== $CIDRAM['BlockInfo']['IPAddr'] && (
    strpos($CIDRAM['BlockInfo']['Signatures'], 'compat_bunnycdn.php') === false
) && empty($DoNotContinue)) {
    $HN = preg_replace('/\s/', '', str_replace("\\", '/', strtolower(urldecode($CIDRAM['Hostname']))));
    $UA = str_replace("\\", '/', strtolower(urldecode($CIDRAM['BlockInfo']['UA'])));
    $UANoSpace = preg_replace('/\s/', '', $UA);

    $Trigger(substr($HN, 0, 2) === '()', 'Bash/Shellshock', '', $InstaBan); // 2017.01.21

    $Trigger(preg_match(
        '/(?:0wn[3e]d|:(?:\{\w:|[\w\d][;:]\})|h[4a]ck(?:e[dr]|ing|[7t](?:[3e' .
        '][4a]m|[0o]{2}l))|%(?:0[0-8bcef]|1)|[`\'"]|^[-.:]|[-.:]$|[.:][\w\d-' .
        ']{64,}[.:])/i',
    $HN), 'Banned hostname', '', $InstaBan); // 2018.06.24

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
        '/(?:prking\.com\.au$|(?:qvt|telsp)\.net\.br$|(?:\.(?:giga-dns|oodle' .
        '|pointandchange|solidseo(?:dedicated|vps)?|topsy|vadino)|23gb|35up|' .
        'accelovation|barefruit|bestprice|colo\.iinet|detangled|kimsufi|ligh' .
        'tspeedsystems|lipperhey|mantraonline|netcomber|onlinehome-server\.m' .
        'yforexvps|page-store|setooz|technicolor)\.com$|poneytelecom\.eu$|(?' .
        ':4u|netadvert|onlinehome-server)\.info$|mobilemarketingaid\.info|\.' .
        'cnr\.it$|kiyosho\.jp$|(?:\.pldt|3fn|buyurl|dragonara|isnet|mfnx|onl' .
        'inehome-server|pool\.ukrtel)\.net$|seomoz\.org$|\.rdsnet\.ro$|(?:di' .
        'margroup|itrack|mail|rulinki|vipmailoffer)\.ru$|(?:2kom|solomono)\.' .
        'ru|\.v4\.ngi\.it|fibersunucu\.com\.tr|awcheck|b(?:oardreader|reakin' .
        'gtopics|uysellsales)|c(?:eptro|heapseovps|yber-uslugi)|drugstore|li' .
        'wio\.|luxuryhandbag|s(?:emalt|mileweb\.com\.ua|quider|tartdedicated' .
        '\.)|(?:exa|fulltextro|we|you?dao)bot)/',
    $HN), 'SEO/Bothost/Scraper/Spamhost'); // 2018.09.17

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
        '~\.(?:as13448|websense)\.|(?:bibbly|pulsepoint|zvelo)\.com|(?:\.fil' .
        'espot|cloudsystemnetworks)\.com$|westdc\.net|propagation\.net$|maje' .
        'stic|meanpath|tag-trek~',
    $HN), 'Unauthorised'); // 2018.09.15

    $Trigger(preg_match('~anchorfree|hotspotsheild|esonicspider\.com$~', $HN), 'Hostile/esonicspider'); // 2018.09.15

    $Trigger(preg_match(
        '/(?:megacom\.biz$|ideastack\.com$|dotnetdotcom\.org$|controlyourself\.online|seeweb\.it)/',
    $HN), 'Hostile/Unauthorised'); // 2017.02.14

    $Trigger(preg_match('~brandaffinity~', $HN), 'Hostile/SLAPP'); // 2018.09.15

    $Trigger(preg_match(
        '/(?:andersdenken\.at$|i(?:g|nsite)\.com\.br$|terra\.cl$|(?:\.(?:app' .
        'ian|bc\.googleusercontent|cloud|ctera|dyn|emc|force|fsfreeware|gnip' .
        '|gridlayer|hosting|icims|panorama|parallels|quest|thegridlayer|voda' .
        '|vultr|webzilla|workday)|10gen|12designer|3leafsystems|3tera|a(?:cc' .
        'entrainc|conex|dvologix|gathon|ltornetworks|mericanforeclosures|mit' .
        'ive|pp(?:irio|istry|jet|nexus|renda|spot|zero)|ptana|riasystems|rju' .
        'na|rtofdefence|sterdata|syanka|uthenticnetworks|zati)|b(?:alticserv' .
        'ers|eam4d|hivesoft|irtondemand|linklogic|lue(?:host|lock|wolf)|oomi' .
        '|ucketexplorer|ungeeconnect)|c(?:a(?:dinor|msolutionsinc|spio|ssatt' .
        '|stiron)|l(?:arioanalytics|ickability|oud(?:42|9analytics|computing' .
        'china|control|era|foundry|kick|scale|status|switch|works)|usterseve' .
        'n)|o(?:ghead|hesiveft|ldlightsolutions|ncur|ntroltier)|tinets)|d(?:' .
        'ata(?:line|sisar|synaps)|edicatedpanel|irectlaw|ns-safe|oclanding|r' .
        'opbox|ynamsoft)|e(?:last(?:ichosts|ra)|n(?:gineyard|omalism|stratus' .
        ')|telos|ucalyptus|vapt|vionet)|fathomdb|flexiscale|followmeoffice|g' .
        '(?:emstone|enerositycool|igaspaces|ogrid|roupcross)|h(?:eroku|exagr' .
        'id|olhost|ost(?:acy|cats|ing24)|ubspan|yperic)|i(?:cloud|modrive|nf' .
        'o(?:bright|rmatica)|tricityhosting)|j(?:oyent|umpbox|unglebox|ustho' .
        'st)|k(?:2analytics|aavo|eynote|nowledgetree)|l(?:ayeredtech|inkneo|' .
        'iveops|oadstorm|ogixml|ongjump|tdomains)|m(?:o(?:derro|jsite|rphexc' .
        'hange|sso|zy)|idphase|turk|ulesoft)|n(?:asstar|e(?:ointeractiva|t(?' .
        ':app|documents|suite|topia)|wrelic|wservers)|ionex|irvanix|ovatium|' .
        'scaled)|o(?:co-inc|nelogin|npathtech|penqrm|psource)|p(?:ara(?:scal' .
        '|tur)e|hatservers|iemontetv|inqidentity|ivotlink|luraprocessing)|q(' .
        '?:layer|rimp|uanti(?:vo|x-uk))|r(?:ackspace(?:cloud)?|e(?:di2|ducti' .
        'velabs|lia(?:blehosting|cloud)|sponsys)|ight(?:now|scale)|ollbase|o' .
        'mania-webhosting|path)|s(?:alesforce|avvis|ertifi|huilinchi|kytap|m' .
        'artservercontrol|naplogic|oasta|pringcm|tax|treetsmarts|uccessmetri' .
        'cs|wifttrim|ymplified|yncplicity)|t(?:aleo|err[ae]mark|h(?:eprocess' .
        'factory|inkgos|oughtexpress)|rustsaas)|utilitystatus|v(?:aultscape|' .
        'ertica|mware|ordel)|web(?:hosting\.uk|scalesolutions)|xactlycorp|xl' .
        'host|xythos|z(?:embly|imory|manda|oho|uora))\.com$|(?:artisticgoals' .
        '|host(?:gator|ingprod)|instantdedicated|khavarzamin|missiondish|new' .
        'slettersrus|profninja|se(?:curityspace|rve(?:path|rbuddies))|viral-' .
        'customers)\.com|(?:(?:\.|kunden)server|clanmoi|fastwebserver|optima' .
        'l|server4you)\.de$|your-server\.de|eucalyptus\.cs\.uscb\.edu$|candy' .
        'cloud\.eu$|adsinmedia\.co\.in$|server\.lu$|iam\.net\.ma$|starnet\.m' .
        'd$|(?:\.(?:bhsrv|box|propagation|voxel)|1978th|collab|emcytown|enki' .
        'consulting|host\.caracastelecom|phicallyon|techajans|visualpleasure' .
        's)\.net$|re(?:liablesite|plyingst)\.net|hitech-hosting\.nl|(?:\.ter' .
        'racotta|beowulf|iboss|memcached|opennebula|xen)\.org$|mor\.ph$|(?:o' .
        'gicom|vampire)\.pl$|(?:cyber-host|slaskdatacenter)\.pl|rivreg\.ru$|' .
        '(?:tkvprok|vympelstroy)\.ru|g\.ho\.st$|(?:webfusion|xcalibre)\.co\.' .
        'uk$|bergdorf-group|cloudsigma|dreamhost|ipxserver|linode|money(?:ma' .
        'ttersnow|tech\.mg)|productsnetworksx|psychz|requestedoffers|scopeho' .
        'sts|s(?:p?lice|teep)host|happyoffer\.club$)/',
    $HN), 'Cloud Service / Server Farm'); // 2018.04.08

    $Trigger(preg_match(
        '/(?:alxagency|capellahealthcare|link88\.seo|ser\.servidor-sainet)\.com/',
    $HN), 'Cloud Service / Server Farm'); // 2018.02.02

    $Trigger(empty($CIDRAM['Ignore']['Agava Ltd']) && preg_match('/agava\.net$/', $HN), 'Agava Ltd'); // 2017.02.06 (ASN 43146)
    $Trigger(empty($CIDRAM['Ignore']['AltusHost B.V']) && preg_match('/altushost\.com$/', $HN), 'AltusHost B.V'); // 2017.02.09 (ASN 51430)
    $Trigger(empty($CIDRAM['Ignore']['Bezeq International']) && preg_match('/bezeqint\.net$/', $HN), 'Bezeq International'); // 2017.02.09 (ASN 8551)
    $Trigger(empty($CIDRAM['Ignore']['Bharti Airtel']) && preg_match('/\.airtelbroadband\.in$/', $HN), 'Bharti Airtel'); // 2017.02.06 (ASNs 9498, 24560, 45514, 45609)
    $Trigger(empty($CIDRAM['Ignore']['ColoCrossing']) && strpos($HN, 'colocrossing.com') !== false, 'ColoCrossing'); // 2017.01.30 (ASN 36352)
    $Trigger(empty($CIDRAM['Ignore']['GorillaServers, Inc']) && strpos($HN, 'gorillaservers') !== false, 'GorillaServers, Inc'); // 2017.02.06 (ASN 53850)
    $Trigger(empty($CIDRAM['Ignore']['HOSTKEY B.V']) && preg_match('/hostkey\.ru$/', $HN), 'HOSTKEY B.V'); // 2017.02.15 (ASN 57043)
    $Trigger(empty($CIDRAM['Ignore']['Host Europe GmbH']) && strpos($HN, 'hosteurope') !== false, 'Host Europe GmbH'); // 2017.01.30 (numerous ASNs)
    $Trigger(empty($CIDRAM['Ignore']['Hostmaster, Ltd']) && strpos($HN, 'fcsrv.net') !== false, 'Hostmaster, Ltd'); // 2018.02.02 (ASN 50968)
    $Trigger(empty($CIDRAM['Ignore']['IDEAL HOSTING']) && strpos($HN, 'idealhosting.net.tr') !== false, 'IDEAL HOSTING'); // 2018.04.08 (ASN 29262)
    $Trigger(empty($CIDRAM['Ignore']['Kyivstar']) && strpos($HN, 'kyivstar') !== false, 'Kyivstar'); // 2017.01.21 (ASNs 12530, 15895, 35081)
    $Trigger(empty($CIDRAM['Ignore']['Leaseweb']) && strpos($HN, 'leaseweb') !== false, 'Leaseweb'); // 2017.02.06 (numerous ASNs)
    $Trigger(empty($CIDRAM['Ignore']['Nobis/Ubiquity']) && preg_match('/(?:nobis|ubiquity)/', $HN), 'Nobis/Ubiquity'); // 2017.02.15 (ASN 15003)
    $Trigger(empty($CIDRAM['Ignore']['QuadraNet, Inc']) && preg_match('/quadranet\.com$/', $HN), 'QuadraNet, Inc'); // 2017.02.14 (ASNs 8100, 29761, 62639)
    $Trigger(empty($CIDRAM['Ignore']['SISTRIX GmbH']) && strpos($HN, 'sistrix') !== false, 'SISTRIX GmbH'); // 2017.01.21 (no ASN)
    $Trigger(empty($CIDRAM['Ignore']['Seznam.cz']) && strpos($HN, 'seznam.cz') !== false, 'Seznam.cz'); // 2017.01.21 (ASNs 43037, 200600)
    $Trigger(empty($CIDRAM['Ignore']['Versaweb, LLC']) && strpos($HN, 'versaweb') !== false, 'Versaweb, LLC'); // 2017.02.14 (ASN 36114)
    $Trigger(empty($CIDRAM['Ignore']['Voxility LLC']) && strpos($HN, 'voxility.net') !== false, 'Voxility LLC'); // 2017.02.06 (ASN 3223)
    $Trigger(empty($CIDRAM['Ignore']['Wowrack.com']) && preg_match('~themothership\.net|wowrack\.com~', $HN), 'Wowrack.com'); // 2018.09.15 (ASN 23033)
    $Trigger(empty($CIDRAM['Ignore']['XEEX']) && strpos($HN, 'xeex') !== false, 'XEEX'); // 2017.01.21 (ASN 27524)

    $Trigger(preg_match(
        '/(?:\.above|shared-server|jkserv)\.net$|akpackaging\.net|(?:academi' .
        'cedge|cyber-freaks|dailyrazor|ibuzytravel|server306|webfaction|\.si' .
        'teprotect)\.com$|(?:aramenet|dinaserver|phishmongers|web(?:hostingh' .
        'ub|sitewelcome))\.com|server4u\.cz$|acetrophies\.co\.uk$|\.pomserve' .
        '2\.co\.uk|webhostserver\.biz$|\.haremo\.de$|webcreators\.nl|rockwel' .
        'lmuseum\.org|skyware\.pl$|vpsnow\.ru$|timeweb\.ru|dailyhealthtipsuk' .
        '\.us$/',
    $HN), 'Probe/Scanner'); // 2018.09.17

    $Trigger(preg_match(
        '/(?:\.oroxy|anonine)\.com$|thefreevpn|vpn(?:999\.com|gate)|public-net/',
    $HN), 'Risky/Proxy/VPN Host'); // 2017.06.25

    $Trigger(preg_match(
        '/(?:(?:dimenoc|dumpyourbitch|hostenko|internetserviceteam|ipredat(?' .
        ':e|or)|krypt|webandnetworksolutions|xcelmg)\.com|mbox\.kz|chello\.p' .
        'l|doctore\.sk|hostnoc\.net|\.(?:host|\.spheral)\.ru)$/',
    $HN), 'Dangerous Host'); // 2018.03.27

    $Trigger(empty($CIDRAM['Ignore']['is74.ru']) && preg_match('/is74\.ru$/', $HN), 'Dangerous Host'); // 2018.03.27 (ASNs 8369, 198675, 199619)
    $Trigger(empty($CIDRAM['Ignore']['ER-Telecom Holding']) && preg_match('/ertelecom\.ru$/', $HN), 'Dangerous Host'); // 2018.03.27 (ASNs 42682, 51570)

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
        !preg_match('/^(?:1(?:27|92\.168)(?:\.1?\d{1,2}|\.2[0-4]\d|\.25[0-5]){2,3}|\:\:1)$/', $CIDRAM['BlockInfo']['IPAddr'])
    ), 'Spoofed/Fake Hostname', '', $InstaBan); // 2018.06.24
    $Trigger(preg_match('/\.local$/', $HN), 'Spoofed/Fake Hostname'); // 2017.02.06

    $Trigger(preg_match(
        '/shodan.\io|(?:serverprofi24|aspadmin|project25499)\./',
    $HN), 'AutoSploit Host'); // 2018.02.02
    // See: http://zb-block.net/zbf/showthread.php?t=25

    $Trigger($HN === '.', 'DNS error', '', $InstaBan); // 2017.02.25

}

/** WordPress cronjob bypass. */
$Bypass(
    (($CIDRAM['BlockInfo']['SignatureCount'] - $Infractions) > 0) &&
    preg_match('~^/wp-cron\.php\?doing_wp_cron=\d+\.\d+$~', $_SERVER['REQUEST_URI']) &&
    defined('DOING_CRON'),
'WordPress cronjob bypass'); // 2018.06.24
