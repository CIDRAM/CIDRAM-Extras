[![Join the chat at https://gitter.im/CIDRAM/Lobby](https://badges.gitter.im/CIDRAM/Lobby.svg)](https://gitter.im/CIDRAM/Lobby)
[![PHP >= 5.4.0](https://img.shields.io/badge/PHP-%3E%3D%205.4.0-8892bf.svg)](https://maikuolan.github.io/Compatibility-Charts/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## CIDRAM-L.

CIDRAM-L, is a lightweight (or "lite") version of CIDRAM.

The entire front-end, Packagist/Composer support, CLI support, Cronable support, and most L10N data has been completely removed from the package. Front-end management, Packagist/Composer support, CLI support, Cronable support, and multilingual support (to an extent) are therefore not available in CIDRAM-L. If you need these things, use the standard CIDRAM package instead. All remaining files pertaining to the "core" component (or core operational files) of CIDRAM have been bundled into a PHAR file. Signature files and configuration remain separate (i.e., not in the PHAR file), as per the standard CIDRAM package. All other customisations (custom themes, modules, signature files, etc) that would otherwise be available in the standard CIDRAM package, remain available to the CIDRAM-L package. Because this is a separate package, all "CIDRAM" identifiers in the package have been changed to "CIDRAM-L" accordingly. Standard minimum requirements per CIDRAM v1 (PHP >= 5.4.0) remain the same for CIDRAM-L v1. Configuration options remain the same (though some mightn't have any effect due to pertaining to things that've been removed from the package, such as front-end management and CLI support).

This package has been made available by special request of some specific users. As this is intended to be a "lite" version of CIDRAM, it is highly unlikely that any additional features will be added in the future. New versions prepared on an as needed basis only. As this package has only been made available by special request, and as it isn't a primary goal of the CIDRAM project, support and development are both likely to be limited. CIDRAM-L had already been marked as legacy, and then deprecated in the past, then made unavailable. As it is now available again, future versions could thus effectively be considered "legacy", but I'll attempt to continue providing support where and when possible.

CIDRAM-L is mostly used in the same way as CIDRAM v2 and prior, except that instead of calling the "loader.php" file, you'll call the "cidram-l.phar" file in your require statements. Unzip the CIDRAM-L package archive (cidram-l.zip), and follow generally the same installation instructions provided for CIDRAM v2 and prior. If you need help, just ask.

The currently available version of CIDRAM-L is "1.27.0".

---


Last Updated: 30 August 2023 (2023.08.30).
