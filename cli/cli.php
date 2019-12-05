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
 * This file: CLI for CIDRAM >= v2 (last modified: 2019.12.05).
 */

/** "CIDRAM" constant needed as sanity check for some required files. */
if (!defined('CIDRAM')) {
    define('CIDRAM', true);
}

/** Version check. */
if (!version_compare(PHP_VERSION, '7.2.0', '>=')) {
    header('Content-Type: text/plain');
    die('[CIDRAM CLI] Not compatible with PHP versions below 7.2.0; Please update PHP in order to use CIDRAM CLI.');
}

/** Create an array for our working data, populate the vault, etc. */
$CIDRAM = ['Direct' => true, 'ML' => false, 'Vault' => __DIR__ . '/vault/'];

/** Kill the script if we can't find the vault directory. */
if (!is_dir($CIDRAM['Vault'])) {
    header('Content-Type: text/plain');
    die('[CIDRAM CLI] Vault directory not correctly set: Can\'t continue.');
}

/** Load each required file or kill the script if any of them don't exist. */
foreach (['functions.php', 'config.php', 'lang.php', 'frontend_functions.php'] as $File) {
    if (!file_exists($CIDRAM['Vault'] . $File)) {
        header('Content-Type: text/plain');
        die('[CIDRAM CLI] ' . $File . ' is missing! Please reinstall CIDRAM.');
    }
    require $CIDRAM['Vault'] . $File;
}

/** Show basic information. */
echo "CIDRAM CLI mode (version/build 2019.338.475).

To test whether an IP address is blocked by CIDRAM:
>> test xxx.xxx.xxx.xxx

To calculate CIDRs from an IP address:
>> cidrs xxx.xxx.xxx.xxx

IPv4/IPv6 are both supported. Multiline input is possible for *all* CLI mode
operations (e.g., to test multiple IP addresses in a single operation) by using
quotes, like so:
>> test \"xxx.xxx.xxx.xxx
>> yyy.yyy.yyy.yyy
>> 2002::1
>> zzz.zzz.zzz.zzz\"

By default, IPs are tested against all signature files, all modules, all
auxiliary rules, *and* against social media and search engine verification.
However, you can optionally disable, on a per-IP basis, checking against
modules with --no-mod, checking against auxiliary rules with --no-aux, and
checking against social media and search engine verification with --no-ssv,
like so:
>> test \"aaa.aaa.aaa.aaa --no-mod
>> bbb.bbb.bbb.bbb --no-aux
>> ccc.ccc.ccc.ccc --no-ssv
>> ddd.ddd.ddd.ddd --no-mod --no-aux --no-ssv\"

To quit, type \"q\" or \"exit\" and press enter.

";

/** Initialise cache. */
$CIDRAM['InitialiseCache']();

/** Usable by events to determine which part of the output generator we're at. */
$CIDRAM['Stage'] = '';

/** Reset bypass flags. */
$CIDRAM['ResetBypassFlags']();

/** Open STDIN. */
$CIDRAM['stdin_handle'] = fopen('php://stdin', 'r');

while (true) {

    /** Set CLI process title (PHP => 5.5.0). */
    if (function_exists('cli_set_process_title')) {
        cli_set_process_title($CIDRAM['ScriptIdent']);
    }

    /** Echo the CLI-mode prompt. */
    echo '>> ';

    /** Wait for user input. */
    $CIDRAM['stdin_clean'] = trim(fgets($CIDRAM['stdin_handle']));

    /** Check whether expected input is multiline. */
    if ($CIDRAM['ML']) {

        /** Multiline detection. */
        if (substr($CIDRAM['stdin_clean'], -1, 1) !== '"') {
            $CIDRAM['Data'][] = $CIDRAM['stdin_clean'];
            continue;
        } else {
            $CIDRAM['Data'][] = substr($CIDRAM['stdin_clean'], 0, -1);
            $CIDRAM['ML'] = false;
            echo "\n";
        }

    } else {

        /** Fetch the command. **/
        $CIDRAM['cmd'] = strtolower(preg_replace('~^([^ ]+).*$~', '\1', $CIDRAM['stdin_clean']));

        /** Multiline detection. */
        if ($CIDRAM['ML'] = (
            substr($CIDRAM['stdin_clean'], strlen($CIDRAM['cmd']) + 1, 1) === '"' &&
            substr($CIDRAM['stdin_clean'], -1, 1) !== '"'
        )) {
            $CIDRAM['Data'] = [substr($CIDRAM['stdin_clean'], strlen($CIDRAM['cmd']) + 2)];
            continue;
        } else {
            $CIDRAM['Data'] = [substr($CIDRAM['stdin_clean'], strlen($CIDRAM['cmd']) + 1)];
            echo "\n";
        }

    }

    /** Set CLI process title with "working" notice (PHP => 5.5.0). */
    if (function_exists('cli_set_process_title')) {
        cli_set_process_title($CIDRAM['ScriptIdent'] . ' - ' . $CIDRAM['L10N']->getString('state_loading'));
    }

    if (!$CIDRAM['ML']) {

        /** Exit CLI-mode. **/
        if ($CIDRAM['cmd'] === 'quit' || $CIDRAM['cmd'] === 'q' || $CIDRAM['cmd'] === 'exit') {
            break;
        }

        /** Perform IP test. **/
        elseif ($CIDRAM['cmd'] === 'test') {
            echo $CIDRAM['L10N']->getString('field_ip_address') . ' – ' . $CIDRAM['L10N']->getString('field_blocked') . "\n===\n";
            foreach ($CIDRAM['Data'] as $CIDRAM['ThisItem']) {
                $CIDRAM['Results'] = ['Mod' => true, 'Aux' => true, 'SSV' => true];
                if (preg_match('~( --no-(?:mod|aux|ssv))+$~', $CIDRAM['ThisItem'])) {
                    if (strpos($CIDRAM['ThisItem'], ' --no-mod') !== false) {
                        $CIDRAM['Results']['Mod'] = false;
                    }
                    if (strpos($CIDRAM['ThisItem'], ' --no-aux') !== false) {
                        $CIDRAM['Results']['Aux'] = false;
                    }
                    if (strpos($CIDRAM['ThisItem'], ' --no-ssv') !== false) {
                        $CIDRAM['Results']['SSV'] = false;
                    }
                    $CIDRAM['ThisItem'] = preg_replace('~( --no-(?:mod|aux|ssv))+$~', '', $CIDRAM['ThisItem']);
                }
                $CIDRAM['SimulateBlockEvent']($CIDRAM['ThisItem'], $CIDRAM['Results']['Mod'], $CIDRAM['Results']['Aux'], $CIDRAM['Results']['SSV']);
                if (
                    $CIDRAM['Caught'] ||
                    empty($CIDRAM['LastTestIP']) ||
                    empty($CIDRAM['TestResults']) ||
                    !empty($CIDRAM['ModuleErrors']) ||
                    !empty($CIDRAM['AuxErrors'])
                ) {
                    $CIDRAM['Results']['YesNo'] = $CIDRAM['L10N']->getString('response_error');
                    if (!empty($CIDRAM['AuxErrors'])) {
                        $CIDRAM['Results']['YesNo'] .= sprintf(
                            ' – auxiliary.yaml (%s)',
                            $CIDRAM['NumberFormatter']->format(count($CIDRAM['AuxErrors']))
                        );
                    }
                    if (!empty($CIDRAM['ModuleErrors'])) {
                        $CIDRAM['ModuleErrorCounts'] = [];
                        foreach ($CIDRAM['ModuleErrors'] as $CIDRAM['ModuleError']) {
                            if (isset($CIDRAM['ModuleErrorCounts'][$CIDRAM['ModuleError'][2]])) {
                                $CIDRAM['ModuleErrorCounts'][$CIDRAM['ModuleError'][2]]++;
                            } else {
                                $CIDRAM['ModuleErrorCounts'][$CIDRAM['ModuleError'][2]] = 1;
                            }
                        }
                        arsort($CIDRAM['ModuleErrorCounts']);
                        foreach ($CIDRAM['ModuleErrorCounts'] as $CIDRAM['ModuleName'] => $CIDRAM['ModuleError']) {
                            $CIDRAM['Results']['YesNo'] .= sprintf(
                                ' – %s (%s)',
                                $CIDRAM['ModuleName'],
                                $CIDRAM['NumberFormatter']->format($CIDRAM['ModuleError'])
                            );
                        }
                        unset($CIDRAM['ModuleName'], $CIDRAM['ModuleError'], $CIDRAM['ModuleErrorCounts']);
                    }
                } elseif ($CIDRAM['BlockInfo']['SignatureCount']) {
                    $CIDRAM['Results']['YesNo'] = $CIDRAM['L10N']->getString('response_yes') . ' – ' . $CIDRAM['BlockInfo']['WhyReason'];
                } else {
                    $CIDRAM['Results']['YesNo'] = $CIDRAM['L10N']->getString('response_no');
                }
                $CIDRAM['Results']['NegateFlags'] = '';
                if ($CIDRAM['Flag Don\'t Log']) {
                    $CIDRAM['Results']['NegateFlags'] .= '📓';
                }
                if ($CIDRAM['Results']['NegateFlags']) {
                    $CIDRAM['Results']['YesNo'] .= ' – 🚫' . $CIDRAM['Results']['NegateFlags'];
                }
                echo $CIDRAM['ThisItem'] . ' – ' . $CIDRAM['Results']['YesNo'] . ".\n";
            }
            unset($CIDRAM['Results']);
            echo "\n";
        }

        /** Calculate CIDRs. **/
        elseif ($CIDRAM['cmd'] === 'cidrs') {
            echo $CIDRAM['L10N']->getString('field_range') . "\n===\n";
            foreach ($CIDRAM['Data'] as $CIDRAM['ThisItem']) {
                if ($CIDRAM['ThisItem'] = preg_replace('~[^\da-f:./]~i', '', $CIDRAM['ThisItem'])) {
                    if (!$CIDRAM['CIDRs'] = $CIDRAM['ExpandIPv4']($CIDRAM['ThisItem'])) {
                        $CIDRAM['CIDRs'] = $CIDRAM['ExpandIPv6']($CIDRAM['ThisItem']);
                    }
                }

                /** Process CIDRs. */
                if (!empty($CIDRAM['CIDRs'])) {
                    $CIDRAM['Factors'] = count($CIDRAM['CIDRs']);
                    array_walk($CIDRAM['CIDRs'], function ($CIDR, $Key) use (&$CIDRAM) {
                        $First = substr($CIDR, 0, strlen($CIDR) - strlen($Key + 1) - 1);
                        if ($CIDRAM['Factors'] === 32) {
                            $Last = $CIDRAM['IPv4GetLast']($First, $Key + 1);
                        } elseif ($CIDRAM['Factors'] === 128) {
                            $Last = $CIDRAM['IPv6GetLast']($First, $Key + 1);
                        } else {
                            $Last = $CIDRAM['L10N']->getString('response_error');
                        }
                        echo $CIDR . ' (' . $First . ' – ' . $Last . ")\n";
                    });
                }
            }
            unset($CIDRAM['CIDRs']);
            echo "\n";
        }

        /** Calculate CIDRs. **/
        elseif ($CIDRAM['cmd'] === 'cidrs') {
            echo $CIDRAM['L10N']->getString('field_range') . "\n===\n";
            foreach ($CIDRAM['Data'] as $CIDRAM['ThisItem']) {
                if ($CIDRAM['ThisItem'] = preg_replace('~[^\da-f:./]~i', '', $CIDRAM['ThisItem'])) {
                    if (!$CIDRAM['CIDRs'] = $CIDRAM['ExpandIPv4']($CIDRAM['ThisItem'])) {
                        $CIDRAM['CIDRs'] = $CIDRAM['ExpandIPv6']($CIDRAM['ThisItem']);
                    }
                }

                /** Process CIDRs. */
                if (!empty($CIDRAM['CIDRs'])) {
                    $CIDRAM['Factors'] = count($CIDRAM['CIDRs']);
                    array_walk($CIDRAM['CIDRs'], function ($CIDR, $Key) use (&$CIDRAM) {
                        $First = substr($CIDR, 0, strlen($CIDR) - strlen($Key + 1) - 1);
                        if ($CIDRAM['Factors'] === 32) {
                            $Last = $CIDRAM['IPv4GetLast']($First, $Key + 1);
                        } elseif ($CIDRAM['Factors'] === 128) {
                            $Last = $CIDRAM['IPv6GetLast']($First, $Key + 1);
                        } else {
                            $Last = $CIDRAM['L10N']->getString('response_error');
                        }
                        echo $CIDR . ' (' . $First . ' – ' . $Last . ")\n";
                    });
                }
            }
            unset($CIDRAM['CIDRs']);
            echo "\n";
        }

        /** Bad command notice. */
        else {
            echo "I don't understand that command, sorry.\n\n";
        }

    }

}
