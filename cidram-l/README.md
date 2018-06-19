[![Join the chat at https://gitter.im/CIDRAM/Lobby](https://badges.gitter.im/CIDRAM/Lobby.svg)](https://gitter.im/CIDRAM/Lobby)
[![PHP >= 5.4.0](https://img.shields.io/badge/PHP-%3E%3D%205.4.0-8892bf.svg)](https://maikuolan.github.io/Compatibility-Charts/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## CIDRAM-L.

CIDRAM-L, is a super-lightweight (or "lite") version of CIDRAM.

The entire front-end, Packagist/Composer support, CLI support, Cronable support, and all language data (L10N data) other than English has been completely removed from the package. Front-end management, Packagist/Composer support, CLI support, Cronable support, and multilingual support are therefore not available in CIDRAM-L. If you need these things, use the standard CIDRAM package instead. All remaining files pertaining to the "core" component (or core operational files) of CIDRAM have been bundled into a PHAR file. Signature files and configuration remain separate (i.e., not in the PHAR file), as per the standard CIDRAM package. All other customisations (custom themes, modules, signature files, etc) that would otherwise be available in the standard CIDRAM package, remain available to the CIDRAM-L package. Because this is a separate package, all "CIDRAM" identifiers in the package have been changed to "CIDRAM-L" accordingly. Standard minimum requirements (PHP >= 5.4.0) remain the same. Configuration options remain the same (though some mightn't have any effect due to pertaining to things that've been removed from the package, such as front-end management and CLI support).

This package has been made available by special request of some specific users. As this is intended to be a "lite" version of CIDRAM, it is highly unlikely that any additional features will be added in the future. New versions prepared on an as needed basis only. As this package has only been made available by special request, and as it isn't a primary goal of the CIDRAM project, support and development are both likely to be limited. CIDRAM-L had already been marked as legacy, and then deprecated in the past, then made unavailable. As it is now available again, future versions could thus effectively be considered "legacy", but I'll attempt to continue providing support where and when possible.

CIDRAM-L is mostly used in the same way as CIDRAM, except that instead of calling the "loader.php" file, you'll call the "cidram-l.phar" file in your require statements. Unzip the CIDRAM-L package archive (cidram-l.zip) in the same way you'd normally unzip the CIDRAM package archive, and follow generally the same installation instructions provided for CIDRAM. If you need help, just ask.

The currently available version of CIDRAM-L is "1.6.1".

- Feb 17, 2018: CIDRAM-L v1.4.1 is forked from CIDRAM v1.4.1, changes made as per the package description above, a new PHAR prepared, and the CIDRAM-L package is committed to GitHub. ALL previous versions of CIDRAM-L are EoL and WON'T be supported anymore under any circumstance.
- Apr 10, 2018: Synced to v1.5.0.
- May 5, 2018: Synced to v1.5.1.
- May 25, 2018: Synced to v1.6.0.
- Jun 8, 2018: CIDRAM-L v1.6.1 released ahead of CIDRAM v1.6.1 due to discovery of a small bug specific to CIDRAM-L.

*Last modified: Jun 8, 2018 (2018.06.19).*
