<?php
/**
 * This file is an optional extension of the CIDRAM package.
 * Homepage: https://cidram.github.io/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: CIDRAM API loader (last modified: 2022.03.02).
 */

namespace CIDRAM\API;

/** "CIDRAM" constant needed as sanity check for some required files. */
if (!defined('CIDRAM')) {
    define('CIDRAM', true);
}

/** Version check. */
if (!version_compare(PHP_VERSION, '7.2.0', '>=')) {
    header('Content-Type: text/plain');
    die('[CIDRAM API] Not compatible with PHP versions below 7.2; Please update PHP in order to use CIDRAM.');
}

/** Create an array for our working data. */
$CIDRAM = [
    'Direct' => false
];

/** Determine the location of the "vault" directory. */
$CIDRAM['Vault'] = __DIR__ . '/vault/';

/** Kill the script if we can't find the vault directory. */
if (!is_dir($CIDRAM['Vault'])) {
    header('Content-Type: text/plain');
    die('[CIDRAM API] Vault directory not correctly set: Can\'t continue.');
}

/** Load each required file or kill the script if any of them don't exist. */
foreach (['functions.php', 'config.php', 'frontend_functions.php'] as $File) {
    if (!file_exists($CIDRAM['Vault'] . $File)) {
        header('Content-Type: text/plain');
        die('[CIDRAM API] ' . $File . ' is missing! Please reinstall CIDRAM.');
    }
    require $CIDRAM['Vault'] . $File;
}

/** Class for OOP implementation. */
class API
{
    /**
     * @var array We'll inherit the $CIDRAM global to this with our constructor.
     */
    public $CIDRAM = [];

    public function __construct(array &$CIDRAM)
    {
        $this->CIDRAM = &$CIDRAM;
    }

    /**
     * Lookup method.
     *
     * @param string|array $Addr The address (or array of addresses) to look up.
     * @param bool $Modules Whether to test against modules. (True = Yes; False = No).
     * @param string $UA An optional custom user agent to cite for the simulated block event.
     * @return array The results of the lookup.
     */
    public function lookup($Addr = '', bool $Modules = false, string $UA = '')
    {
        $CIDRAM = &$this->CIDRAM;
        $CIDRAM['FE'] = $UA ? ['custom-ua' => $UA] : [];
        if (is_array($Addr)) {
            $Results = [];
            foreach ($Addr as $ThisAddr) {
                $CIDRAM['SimulateBlockEvent']($ThisAddr, $Modules);
                $Results[$ThisAddr] = $CIDRAM['BlockInfo'];
            }
            return $Results;
        }
        $CIDRAM['SimulateBlockEvent']($Addr, $Modules);
        return $CIDRAM['BlockInfo'];
    }
}
