<?php
namespace CIDRAM\API;

/**
 * This file is an optional extension of the CIDRAM package.
 * Homepage: https://cidram.github.io/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: CIDRAM API loader (last modified: 2020.11.29).
 */

/** "CIDRAM" constant needed as sanity check for some required files. */
if (!defined('CIDRAM')) {
    define('CIDRAM', true);
}

/** Version check. */
if (!version_compare(PHP_VERSION, '5.4.0', '>=')) {
    header('Content-Type: text/plain');
    die('[CIDRAM API] Not compatible with PHP versions below 5.4.0; Please update PHP in order to use CIDRAM.');
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
foreach (['functions.php', 'config.php', 'lang.php', 'frontend_functions.php'] as $File) {
    if (!file_exists($CIDRAM['Vault'] . $File)) {
        header('Content-Type: text/plain');
        die('[CIDRAM API] ' . $File . ' is missing! Please reinstall CIDRAM.');
    }
    require $CIDRAM['Vault'] . $File;
}

/** Class for OOP implementation. */
class API
{

    /** We'll inherit the $CIDRAM global to this with our constructor. */
    public $CIDRAM = [];

    public function __construct(array &$CIDRAM)
    {
        $this->CIDRAM = &$CIDRAM;
    }

    public function lookup($Addr = '', $Modules = false, $UA = '')
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
