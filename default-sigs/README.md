Contains the default signature files, minus the bogon sections (I usually add the bogon sections to the working files
after "fixing" them using the "signature fixer"), both "fixed" and "nonfixed".

Nonfixed = The working files (with minimal aggregation, the files that I work from when maintaining the default
signatures; in this context, maintaining can refer to adding to, editing, and deleting from the default signatures).

Fixed = The working files (the "nonfixed"), after validating, aggregating and fixing them by way of running them
through the internal "signature fixer" feature of CIDRAM (ergo, "fixed").

The final resulting signature files (all fixed and with bogon sections included) can be found in the main/core
repository (but won't be included in this respository, as to avoid duplication and potential confusion).
