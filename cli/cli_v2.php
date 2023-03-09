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
 * This file: CLI for CIDRAM >= v2 (last modified: 2023.03.09).
 */

/** "CIDRAM" constant needed as sanity check for some required files. */
if (!defined('CIDRAM')) {
    define('CIDRAM', true);
}

/** Version check. */
if (!version_compare(PHP_VERSION, '7.2.0', '>=')) {
    header('Content-Type: text/plain');
    die('[CIDRAM CLI] Not compatible with PHP versions below 7.2; Please update PHP in order to use CIDRAM CLI.');
}

/** Create an array for our working data, populate the vault, etc. */
$CIDRAM = ['Direct' => true, 'ML' => false, 'Vault' => __DIR__ . '/vault/', 'Chain' => ''];

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

/**
 * Ensure that CLI is being accessed from the correct endpoint (i.e., not from
 * a webserver).
 */
if (
    !empty($_SERVER['REQUEST_METHOD']) ||
    substr(php_sapi_name(), 0, 3) !== 'cli' ||
    !empty($CIDRAM['IPAddr']) ||
    !empty($_SERVER['HTTP_USER_AGENT']) ||
    (
        isset($_SERVER['SCRIPT_FILENAME']) &&
        str_replace("\\", '/', strtolower(realpath($_SERVER['SCRIPT_FILENAME']))) !== str_replace("\\", '/', strtolower(__FILE__))
    )
) {
    header('Content-Type: text/plain');
    die('[CIDRAM CLI] Webserver access not permitted.');
}

/** Show basic information. */
echo "CIDRAM CLI mode (build 2023.67.0 for v2).

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

You can also use commas instead if you want (this is treated the same as using
multilines, but you won't need to use quotes, and don't mix both together):
>> test xxx.xxx.xxx.xxx,yyy.yyy.yyy.yyy,2002::1,zzz.zzz.zzz.zzz

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

You can also read from files like so:
>> fread \"file1.dat
>> file2.dat
>> file3.dat\"

You can also write to files like so:
>> fwrite=file.dat

You can also aggregate IPs and CIDRs like so:
>> aggregate \"1.2.3.4/32
>> 1.2.3.5/32
>> 1.2.3.6/32
>> 1.2.3.7/32\"

Or, to aggregate them as netmasks:
>> aggregate=netmasks \"1.2.3.4/32
>> 1.2.3.5/32\"

You can also chain commands together like so (this example reads from some
files, aggregates their content, then writes the aggregated data to output.dat):
>> fread>aggregate>fwrite=output.dat \"input1.dat
>> input2.dat
>> input3.dat\"

Or, depending on whether you'd prefer to chain first to last, or last to first:
>> fwrite=output.dat<aggregate<fread \"input1.dat
>> input2.dat
>> input3.dat\"

Or, using commas instead of multilines (does exactly the same thing):
>> fread>aggregate>fwrite=output.dat input1.dat,input2.dat,input3.dat

You can print data to the screen like so (this can sometimes be useful when
chaining commands):
>> print Hello World

You can also utilise CIDRAM's signature fixer facility via CLI:
>> fread>fix>fwrite=fixed.dat broken.dat

To quit, type \"q\", \"quit\", or \"exit\" and press enter:
>> q

";

/** Initialise cache. */
$CIDRAM['InitialiseCache']();

/** Usable by events to determine which part of the output generator we're at. */
$CIDRAM['Stage'] = '';

/** Reset bypass flags. */
$CIDRAM['ResetBypassFlags']();

/** Open STDIN. */
$CIDRAM['stdin_handle'] = fopen('php://stdin', 'rb');

while (true) {
    /** Set CLI process title. */
    if (function_exists('cli_set_process_title')) {
        cli_set_process_title($CIDRAM['ScriptIdent']);
    }

    /** Echo the CLI-mode prompt. */
    if (!$CIDRAM['Chain']) {
        echo '>> ';
    }

    /** Wait for user input or assume it from chaining. */
    $CIDRAM['stdin_clean'] = $CIDRAM['Chain'] ?: trim(fgets($CIDRAM['stdin_handle']));

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
        /** Fetch the command. */
        if (($CIDRAM['SPos'] = strpos($CIDRAM['stdin_clean'], ' ')) === false) {
            $CIDRAM['cmd'] = $CIDRAM['stdin_clean'];
        } else {
            $CIDRAM['cmd'] = substr($CIDRAM['stdin_clean'], 0, $CIDRAM['SPos']);
        }

        /** Chain detection. */
        if ($CIDRAM['Chain']) {
            $CIDRAM['Data'] = explode("\n", substr($CIDRAM['stdin_clean'], strlen($CIDRAM['cmd']) + 1));
        } else {
            /** Multiline detection. */
            if ($CIDRAM['ML'] = (
                substr($CIDRAM['stdin_clean'], strlen($CIDRAM['cmd']) + 1, 1) === '"' &&
                substr($CIDRAM['stdin_clean'], -1, 1) !== '"'
            )) {
                $CIDRAM['Data'] = [substr($CIDRAM['stdin_clean'], strlen($CIDRAM['cmd']) + 2)];
                continue;
            } else {
                $CIDRAM['Data'] = substr($CIDRAM['stdin_clean'], strlen($CIDRAM['cmd']) + 1);
                if (substr($CIDRAM['Data'], 0, 1) === '"' && substr($CIDRAM['Data'], -1, 1) === '"') {
                    $CIDRAM['Data'] = substr($CIDRAM['Data'], 1, -1);
                }
                if (strpos($CIDRAM['Data'], ',') !== false) {
                    $CIDRAM['Data'] = explode(',', $CIDRAM['Data']);
                } else {
                    $CIDRAM['Data'] = [$CIDRAM['Data']];
                }
                echo "\n";
            }
        }
    }

    /** Chain processing. */
    if (($CIDRAM['ChainPos'] = strpos($CIDRAM['cmd'], '>')) !== false && strpos($CIDRAM['cmd'], '<') === false) {
        $CIDRAM['Chain'] = substr($CIDRAM['cmd'], $CIDRAM['ChainPos'] + 1) . ' ';
        $CIDRAM['cmd'] = substr($CIDRAM['cmd'], 0, $CIDRAM['ChainPos']);
    } elseif (strpos($CIDRAM['cmd'], '>') === false && ($CIDRAM['ChainPos'] = strrpos($CIDRAM['cmd'], '<')) !== false) {
        $CIDRAM['Chain'] = substr($CIDRAM['cmd'], 0, $CIDRAM['ChainPos']) . ' ';
        $CIDRAM['cmd'] = substr($CIDRAM['cmd'], $CIDRAM['ChainPos'] + 1);
    } else {
        $CIDRAM['Chain'] = '';
    }

    /** Set CLI process title with "working" notice. */
    if (function_exists('cli_set_process_title')) {
        cli_set_process_title($CIDRAM['ScriptIdent'] . ' - ' . $CIDRAM['L10N']->getString('state_loading'));
    }

    /** Don't execute any commands when receiving multiline input. */
    if ($CIDRAM['ML']) {
        continue;
    }

    /** Exit CLI-mode. */
    if ($CIDRAM['cmd'] === 'quit' || $CIDRAM['cmd'] === 'q' || $CIDRAM['cmd'] === 'exit') {
        break;
    }

    /** Print data to the screen. */
    if ($CIDRAM['cmd'] === 'print') {
        if (empty($CIDRAM['Data']) || (count($CIDRAM['Data']) === 1 && empty($CIDRAM['Data'][0]))) {
            echo "There's nothing to print, sorry.\n\n";
            continue;
        }
        if (!$CIDRAM['Chain']) {
            foreach ($CIDRAM['Data'] as $CIDRAM['ThisItem']) {
                echo $CIDRAM['ThisItem'] . "\n";
            }
            echo "\n";
            continue;
        }
        $CIDRAM['Chain'] = '';
        echo "The print command can't be chained in that way, sorry.\n\n";
        continue;
    }

    /** Write data to a file. */
    if (substr($CIDRAM['cmd'], 0, 7) === 'fwrite=') {
        if (empty($CIDRAM['Data']) || (count($CIDRAM['Data']) === 1 && empty($CIDRAM['Data'][0]))) {
            echo "There's nothing to write, sorry.\n\n";
            continue;
        }
        if ($CIDRAM['Chain']) {
            echo "The fwrite command can't be chained in that way, sorry.\n\n";
            continue;
        }
        $CIDRAM['WriteTo'] = substr($CIDRAM['cmd'], 7);
        if (is_dir($CIDRAM['Vault'] . $CIDRAM['WriteTo']) || !is_writable($CIDRAM['Vault'])) {
            echo "I can't write to " . $CIDRAM['WriteTo'] . ", sorry.\n\n";
            continue;
        }
        $CIDRAM['Handle'] = fopen($CIDRAM['Vault'] . $CIDRAM['WriteTo'], 'wb');
        $CIDRAM['BlocksToDo'] = count($CIDRAM['Data']);
        $CIDRAM['ThisBlock'] = 0;
        $CIDRAM['Filesize'] = 0;
        foreach ($CIDRAM['Data'] as $CIDRAM['ThisItem']) {
            $CIDRAM['ThisBlock']++;
            $CIDRAM['Filesize'] += strlen($CIDRAM['ThisItem']);
            if ($CIDRAM['ThisBlock'] !== $CIDRAM['BlocksToDo']) {
                $CIDRAM['ThisItem'] .= "\n";
                $CIDRAM['Filesize']++;
            }
            fwrite($CIDRAM['Handle'], $CIDRAM['ThisItem']);
        }
        fclose($CIDRAM['Handle']);
        $CIDRAM['MemoryUsage'] = memory_get_usage();
        $CIDRAM['FormatFilesize']($CIDRAM['MemoryUsage']);
        $CIDRAM['FormatFilesize']($CIDRAM['Filesize']);
        echo 'Finished writing to ' . $CIDRAM['WriteTo'] . '. <' . $CIDRAM['L10N']->getString('field_file') . ': ' . $CIDRAM['Filesize'] . '> <RAM: ' . $CIDRAM['MemoryUsage'] . ">\n\n";
        unset($CIDRAM['WriteTo'], $CIDRAM['Handle'], $CIDRAM['BlocksToDo'], $CIDRAM['ThisBlock'], $CIDRAM['MemoryUsage'], $CIDRAM['Filesize']);
        continue;
    }

    /** Read data from files. */
    if ($CIDRAM['cmd'] === 'fread') {
        if (!$CIDRAM['Chain']) {
            echo "I'm not sure what to do with the file's data after reading it.\nPlease chain fread to something else so that I'll know what to do. Thanks.\n\n";
            continue;
        }
        foreach ($CIDRAM['Data'] as $CIDRAM['ThisItem']) {
            $CIDRAM['ThisItemTry'] = $CIDRAM['Vault'] . $CIDRAM['ThisItem'];
            if (!is_file($CIDRAM['ThisItemTry']) || !is_readable($CIDRAM['ThisItemTry'])) {
                $CIDRAM['ThisItemTry'] = $CIDRAM['ThisItem'];
                if (!is_file($CIDRAM['ThisItemTry']) || !is_readable($CIDRAM['ThisItemTry'])) {
                    echo "Failed to read " . $CIDRAM['ThisItem'] . "!\n";
                    continue;
                }
            }
            $CIDRAM['ThisItemSize'] = filesize($CIDRAM['ThisItemTry']);
            $CIDRAM['Filesize'] = $CIDRAM['ThisItemSize'];
            $CIDRAM['FormatFilesize']($CIDRAM['Filesize']);
            $CIDRAM['ThisItemSize'] = $CIDRAM['ThisItemSize'] ? ceil($CIDRAM['ThisItemSize'] / 131072) : 0;
            if ($CIDRAM['ThisItemSize'] <= 0) {
                echo "Failed to read " . $CIDRAM['ThisItem'] . "!\n";
                continue;
            }
            $CIDRAM['ThisItemTry'] = fopen($CIDRAM['ThisItemTry'], 'rb');
            $CIDRAM['ThisItemCycle'] = 0;
            while ($CIDRAM['ThisItemCycle'] < $CIDRAM['ThisItemSize']) {
                $CIDRAM['Chain'] .= fread($CIDRAM['ThisItemTry'], 131072);
                $CIDRAM['ThisItemCycle']++;
            }
            $CIDRAM['MemoryUsage'] = memory_get_usage();
            $CIDRAM['FormatFilesize']($CIDRAM['MemoryUsage']);
            echo 'Finished reading from ' . $CIDRAM['ThisItem'] . '. <' . $CIDRAM['L10N']->getString('field_file') . ': ' . $CIDRAM['Filesize'] . '> <RAM: ' . $CIDRAM['MemoryUsage'] . ">\n";
            fclose($CIDRAM['ThisItemTry']);
        }
        unset($CIDRAM['ThisItemTry'], $CIDRAM['ThisItemSize'], $CIDRAM['Filesize'], $CIDRAM['ThisItemCycle'], $CIDRAM['MemoryUsage']);
        echo "\n";
        continue;
    }

    /** Perform IP test. */
    if ($CIDRAM['cmd'] === 'test') {
        if (!$CIDRAM['Chain']) {
            echo $CIDRAM['L10N']->getString('field_ip_address') . ' – ' . $CIDRAM['L10N']->getString('field_blocked') . "\n===\n";
        }
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
            if ($CIDRAM['Chain']) {
                $CIDRAM['Chain'] .= $CIDRAM['ThisItem'] . ' – ' . $CIDRAM['Results']['YesNo'] . ".\n";
            } else {
                echo $CIDRAM['ThisItem'] . ' – ' . $CIDRAM['Results']['YesNo'] . ".\n";
            }
        }
        unset($CIDRAM['Results']);
        if (!$CIDRAM['Chain']) {
            echo "\n";
        }
        continue;
    }

    /** Calculate CIDRs. */
    if ($CIDRAM['cmd'] === 'cidrs') {
        if (!$CIDRAM['Chain']) {
            echo $CIDRAM['L10N']->getString('field_range') . "\n===\n";
        }
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
                    if ($CIDRAM['Chain']) {
                        $CIDRAM['Chain'] .= $CIDR . "\n";
                    } else {
                        $First = substr($CIDR, 0, strlen($CIDR) - strlen($Key + 1) - 1);
                        if ($CIDRAM['Factors'] === 32) {
                            $Last = $CIDRAM['IPv4GetLast']($First, $Key + 1);
                        } elseif ($CIDRAM['Factors'] === 128) {
                            $Last = $CIDRAM['IPv6GetLast']($First, $Key + 1);
                        } else {
                            $Last = $CIDRAM['L10N']->getString('response_error');
                        }
                        echo $CIDR . ' (' . $First . ' – ' . $Last . ")\n";
                    }
                });
            }
        }
        unset($CIDRAM['CIDRs']);
        if (!$CIDRAM['Chain']) {
            echo "\n";
        }
        continue;
    }

    /** Aggregate IPs/CIDRs. */
    if ($CIDRAM['cmd'] === 'aggregate' || substr($CIDRAM['cmd'], 0, 10) === 'aggregate=') {
        echo $CIDRAM['L10N']->getString('link_ip_aggregator') . "\n===\n";
        $CIDRAM['OutputFormat'] = (substr($CIDRAM['cmd'], 10) === 'netmasks') ? 1 : 0;
        $CIDRAM['Aggregator'] = new \CIDRAM\Aggregator\Aggregator($CIDRAM, $CIDRAM['OutputFormat']);
        $CIDRAM['Data'] = implode("\n", $CIDRAM['Data']);
        $CIDRAM['Data'] = str_replace("\r", '', trim($CIDRAM['Data']));
        $CIDRAM['Results'] = ['In' => 0, 'Rejected' => 0, 'Accepted' => 0, 'Merged' => 0, 'Out' => 0, 'Parse' => 0, 'Tick' => 0, 'Measure' => 0];
        $CIDRAM['Timer'] = 0;
        $CIDRAM['Aggregator']->callbacks['newParse'] = function ($Measure) use (&$CIDRAM) {
            if ($CIDRAM['Results']['Parse'] !== 0) {
                $Memory = memory_get_usage();
                $CIDRAM['FormatFilesize']($Memory);
                echo "\rParse " . $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['Parse']) . ' ... ' . $CIDRAM['NumberFormatter']->format(100, 2) . '% (' . $CIDRAM['TimeFormat'](time(), $CIDRAM['Config']['general']['time_format']) . ') <RAM: ' . $Memory . '>';
            }
            echo "\n";
            $CIDRAM['Results']['Parse']++;
            $CIDRAM['Results']['Tick'] = 0;
            $CIDRAM['Results']['Timer'] = 0;
            $CIDRAM['Results']['Measure'] = $Measure ?: $CIDRAM['Results']['In'];
        };
        $CIDRAM['Aggregator']->callbacks['newTick'] = function () use (&$CIDRAM) {
            $CIDRAM['Results']['Tick']++;
            $CIDRAM['Timer']++;
            if ($CIDRAM['Results']['Tick'] >= $CIDRAM['Results']['Measure']) {
                $CIDRAM['Results']['Measure']++;
            }
            if ($CIDRAM['Timer'] > 25) {
                $CIDRAM['Timer'] = 0;
                $Percent = $CIDRAM['NumberFormatter']->format(($CIDRAM['Results']['Tick'] / $CIDRAM['Results']['Measure']) * 100, 2);
                echo "\rParse " . $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['Parse']) . ' ... ' . $Percent . '%';
            }
        };
        $CIDRAM['Data'] = $CIDRAM['Aggregator']->aggregate($CIDRAM['Data']);
        $CIDRAM['Results']['Memory'] = memory_get_usage();
        $CIDRAM['FormatFilesize']($CIDRAM['Results']['Memory']);
        echo "\rParse " . $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['Parse']) . ' ... ' . $CIDRAM['NumberFormatter']->format(100, 2) . '% (' . $CIDRAM['TimeFormat'](time(), $CIDRAM['Config']['general']['time_format']) . ') <RAM: ' . $CIDRAM['Results']['Memory'] . ">\n\n";
        echo sprintf(
            $CIDRAM['L10N']->getString('label_results'),
            $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['In']),
            $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['Rejected']),
            $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['Accepted']),
            $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['Merged']),
            $CIDRAM['NumberFormatter']->format($CIDRAM['Results']['Out'])
        ) . "\n\n";
        if ($CIDRAM['Chain']) {
            $CIDRAM['Chain'] .= $CIDRAM['Data'];
        } else {
            echo $CIDRAM['Data'] . "\n\n";
        }
        unset($CIDRAM['Results'], $CIDRAM['Timer'], $CIDRAM['Aggregator'], $CIDRAM['OutputFormat']);
        continue;
    }

    /** Create analysis matrix. */
    if (class_exists('\Maikuolan\Common\Matrix') && function_exists('imagecreatetruecolor') && substr($CIDRAM['cmd'], 0, 7) === 'matrix=') {
        if (empty($CIDRAM['Data']) || (count($CIDRAM['Data']) === 1 && empty($CIDRAM['Data'][0]))) {
            echo "There's nothing to analyse, sorry.\n\n";
            continue;
        }
        if ($CIDRAM['Chain']) {
            echo "The matrix command can't be chained in that way, sorry.\n\n";
            continue;
        }
        $CIDRAM['WriteTo'] = substr($CIDRAM['cmd'], 7);
        if (is_dir($CIDRAM['Vault'] . $CIDRAM['WriteTo']) || !is_writable($CIDRAM['Vault'])) {
            echo "I can't write to " . $CIDRAM['WriteTo'] . ", sorry.\n\n";
            continue;
        }
        $CIDRAM['Data'] = implode("\n", $CIDRAM['Data']);
        $CIDRAM['Matrix-Create']($CIDRAM['Data'], $CIDRAM['WriteTo'], true);
        unset($CIDRAM['WriteTo']);
        continue;
    }

    /** Signature file fixer. */
    if ($CIDRAM['cmd'] === 'fix') {
        echo $CIDRAM['L10N']->getString('link_fixer') . "\n===\n";
        $CIDRAM['Data'] = implode("\n", $CIDRAM['Data']);
        $CIDRAM['Fixer'] = [
            'Aggregator' => new \CIDRAM\Aggregator\Aggregator($CIDRAM),
            'Before' => hash('sha256', $CIDRAM['Data']) . ':' . strlen($CIDRAM['Data']),
            'Timer' => 0,
            'Parse' => 0,
            'Tick' => 0,
            'Measure' => 0,
        ];
        $CIDRAM['Fixer']['Aggregator']->callbacks['newParse'] = function ($Measure) use (&$CIDRAM) {
            if ($CIDRAM['Fixer']['Parse'] !== 0) {
                $Memory = memory_get_usage();
                $CIDRAM['FormatFilesize']($Memory);
                echo "\rParse " . $CIDRAM['NumberFormatter']->format($CIDRAM['Fixer']['Parse']) . ' ... ' . $CIDRAM['NumberFormatter']->format(100, 2) . '% (' . $CIDRAM['TimeFormat'](time(), $CIDRAM['Config']['general']['time_format']) . ') <RAM: ' . $Memory . '>';
            }
            echo "\n";
            $CIDRAM['Fixer']['Parse']++;
            $CIDRAM['Fixer']['Tick'] = 0;
            $CIDRAM['Fixer']['Timer'] = 0;
            $CIDRAM['Fixer']['Measure'] = $Measure;
        };
        $CIDRAM['Fixer']['Aggregator']->callbacks['newTick'] = function () use (&$CIDRAM) {
            $CIDRAM['Fixer']['Tick']++;
            $CIDRAM['Fixer']['Timer']++;
            if ($CIDRAM['Fixer']['Tick'] >= $CIDRAM['Fixer']['Measure']) {
                $CIDRAM['Fixer']['Measure']++;
            }
            if ($CIDRAM['Fixer']['Timer'] > 25) {
                $CIDRAM['Fixer']['Timer'] = 0;
                $Percent = $CIDRAM['NumberFormatter']->format(($CIDRAM['Fixer']['Tick'] / $CIDRAM['Fixer']['Measure']) * 100, 2);
                echo "\rParse " . $CIDRAM['NumberFormatter']->format($CIDRAM['Fixer']['Parse']) . ' ... ' . $Percent . '%';
            }
        };
        if (strpos($CIDRAM['Data'], "\r") !== false) {
            $CIDRAM['Data'] = str_replace("\r", '', $CIDRAM['Data']);
        }
        $CIDRAM['Fixer']['StrObject'] = new \Maikuolan\Common\ComplexStringHandler(
            "\n" . $CIDRAM['Data'] . "\n",
            '~(?<=\n)(?:\n|Expires: \d{4}\.\d\d\.\d\d|Origin: [A-Z]{2}|(?:\#|Tag: |Profile: |Defers to: )[^\n]+| *\/\*\*(?:\n *\*[^\n]*)*\/| *\/\*\*? [^\n*]+\*\/|---\n(?:[^\n:]+:(?:\n +[^\n:]+: [^\n]+)+)+)+\n~',
            function ($Data) use (&$CIDRAM) {
                if (!$Data = trim($Data)) {
                    return '';
                }
                $Output = '';
                $EoLPos = $NEoLPos = 0;
                while ($NEoLPos !== false) {
                    $Set = $Previous = '';
                    while (true) {
                        if (($NEoLPos = strpos($Data, "\n", $EoLPos)) === false) {
                            $Line = trim(substr($Data, $EoLPos));
                        } else {
                            $Line = trim(substr($Data, $EoLPos, $NEoLPos - $EoLPos));
                            $NEoLPos++;
                        }
                        $Param = (($Pos = strpos($Line, ' ')) !== false) ? substr($Line, $Pos + 1) : 'Deny Generic';
                        $Param = preg_replace(['~^\s+|\s+$~', '~(\S+)\s+(\S+)~'], ['', '\1 \2'], $Param);
                        if ($Previous === '') {
                            $Previous = $Param;
                        }
                        if ($Param !== $Previous) {
                            $NEoLPos = 0;
                            break;
                        }
                        if ($Line) {
                            $Set .= $Line . "\n";
                        }
                        if ($NEoLPos === false) {
                            break;
                        }
                        $EoLPos = $NEoLPos;
                    }
                    $CIDRAM['Results'] = ['In' => 0, 'Rejected' => 0, 'Accepted' => 0, 'Merged' => 0, 'Out' => 0];
                    if ($Set = $CIDRAM['Fixer']['Aggregator']->aggregate(trim($Set))) {
                        $Set = preg_replace('~$~m', ' ' . $Previous, $Set);
                        $Output .= $Set . "\n";
                    }
                }
                return trim($Output);
            }
        );
        $CIDRAM['Fixer']['StrObject']->iterateClosure(function (string $Data) use (&$CIDRAM) {
            if (($Pos = strpos($Data, "---\n")) !== false && substr($Data, $Pos - 1, 1) === "\n") {
                $YAML = substr($Data, $Pos + 4);
                if (($HPos = strpos($YAML, "\n#")) !== false) {
                    $After = substr($YAML, $HPos);
                    $YAML = substr($YAML, 0, $HPos + 1);
                } else {
                    $After = '';
                }
                $BeforeCount = substr_count($YAML, "\n");
                $Arr = [];
                $CIDRAM['YAML']->process($YAML, $Arr);
                $NewData = substr($Data, 0, $Pos + 4) . $CIDRAM['YAML']->reconstruct($Arr);
                if (($Add = $BeforeCount - substr_count($NewData, "\n") + 1) > 0) {
                    $NewData .= str_repeat("\n", $Add);
                }
                $NewData .= $After;
                if ($Data !== $NewData) {
                    $Data = $NewData;
                }
            }
            return "\n" . $Data;
        }, true);
        $CIDRAM['Fixer']['Memory'] = memory_get_usage();
        $CIDRAM['FormatFilesize']($CIDRAM['Fixer']['Memory']);
        echo "\rParse " . $CIDRAM['NumberFormatter']->format($CIDRAM['Fixer']['Parse']) . ' ... ' . $CIDRAM['NumberFormatter']->format(100, 2) . '% (' . $CIDRAM['TimeFormat'](time(), $CIDRAM['Config']['general']['time_format']) . ') <RAM: ' . $CIDRAM['Fixer']['Memory'] . ">\n\n";
        $CIDRAM['Data'] = trim($CIDRAM['Fixer']['StrObject']->recompile()) . "\n";
        $CIDRAM['Fixer']['After'] = hash('sha256', $CIDRAM['Data']) . ':' . strlen($CIDRAM['Data']);
        echo 'Checksum before: ' . $CIDRAM['Fixer']['Before'] . "\nChecksum after: " . $CIDRAM['Fixer']['After'] . "\n\n";
        unset($CIDRAM['Fixer']);
        if ($CIDRAM['Chain']) {
            $CIDRAM['Chain'] .= $CIDRAM['Data'];
        } else {
            echo $CIDRAM['Data'] . "\n\n";
        }
        continue;
    }

    /** Reset the chain if the current command isn't valid. */
    $CIDRAM['Chain'] = '';

    /** Let the user know that the current command isn't valid. */
    echo "I don't understand that command, sorry.\n\n";
}
