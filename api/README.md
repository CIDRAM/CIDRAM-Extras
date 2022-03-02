### CIDRAM API loader.

The CIDRAM API loader is useful if you want to integrate the functionality that CIDRAM provides into an already existing solution without needing to reorganise your stack. It provides a way to load CIDRAM and access its functionality *without* performing any automated checks against the IP of the page request, or performing any of the other automated procedures that CIDRAM would normally perform during the course of its execution (if you want these automated checks and automated procedures, just install CIDRAM and its hooks normally).

To use the CIDRAM API loader, install CIDRAM, but don't install any of its hooks anywhere. Copy the API loader (either `api_v2.php` if you're using CIDRAM v2, or `api_v3.php` if you're using CIDRAM v3) to the base directory of your CIDRAM installation (the same directory containing the `loader.php` file), and instead of hooking `loader.php` anywhere, hook the API loader to whichever script or package needs CIDRAM and its functionality.

Example:

```PHP
require '/foo/bar/public_html/cidram/api_vx.php';
```

From there, you can access the functionality that CIDRAM provides by your choice of either an object-oriented approach, or a closure-based approach (both assume that you've required/hooked the API loader to wherever the functionality is needed).

*Note: In either case, be careful about naming any variables "CIDRAM", due to that CIDRAM writes all its data to a global array by that name, and naming a new variable by that name could overwrite that array, causing CIDRAM to cease functioning at all.*

### Object-oriented approach.

Create a new object from the class `\CIDRAM\API\API`. A public variable will exist in the object, "CIDRAM", that should contain all closures and all data normally available to CIDRAM, as well as a public method, "lookup".

"lookup" accepts three parameters. The first parameter is either a string or an array of strings representing the IPs that you want to look up using CIDRAM. The second parameter is an optional boolean (defaults to false) indicating whether to check only against signature files, or also against modules (false for just signature files; true for both signature files and modules). The third parameter is an optional string indicating the user agent that should be assumed when looking up the IPs (if omitted or empty, "SimulateBlockEvent" will be assumed). Either an array or an array of arrays (depending on whether a string or an array of strings was entered as the first parameter) will be returned, each array containing the "BlockInfo" (containing the results of the lookup) corresponding to each IP looked up.

Example (for single IPs):

```PHP
$Foo = new \CIDRAM\API\API($CIDRAM);
$Bar = $Foo->lookup('1.2.3.4', false, 'Foobar');
var_dump($Bar);
```

Example (for multiple IPs):

```PHP
$Foo = new \CIDRAM\API\API($CIDRAM);
$Bar = $Foo->lookup(['1.2.3.4', '1.2.3.5', '1.2.3.6', '1.2.3.7'], false, 'Foobar');
var_dump($Bar);
```

### Closure-based approach.

You can call the closures that exist in the codebase of CIDRAM directly. In particular, there's a closure named "SimulateBlockEvent" that you can use to look up IPs with CIDRAM. "SimulateBlockEvent" is an element of the "CIDRAM" global array, and it accepts three parameters. The first parameter is a string representing the IP that you want to look up using CIDRAM. The second parameter is an optional boolean (defaults to false) indicating whether to check only against signature files, or also against modules (false for just signature files; true for both signature files and modules). The third parameter is an optional string indicating the user agent that should be assumed when looking up the IP (if omitted or empty, "SimulateBlockEvent" will be assumed). No data is returned directly, but the results of the lookup can be accessed via the "BlockInfo" array in the "CIDRAM" global array.

Example (for single IPs):

```PHP
$CIDRAM['SimulateBlockEvent']('1.2.3.4', false, 'Foobar');
var_dump($CIDRAM['BlockInfo']);
```

Example (for multiple IPs):

```PHP
$Foo = [];
foreach (['1.2.3.4', '1.2.3.5', '1.2.3.6', '1.2.3.7'] as $IP) {
    $CIDRAM['SimulateBlockEvent']($IP, false, 'Foobar');
    $Foo[$IP] = $CIDRAM['BlockInfo'];
}
var_dump($Foo);
```

---


Last Updated: 2 March 2022 (2022.03.02).
