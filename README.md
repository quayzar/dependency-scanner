Dependency Scanner
==================

This script scans a project for outdated or vulnerable dependencies. While it currently only supports Python projects with the default dependency list (`requirements.txt`), it could easily be extended to support other Python-specific dependency lists (e.g. `Pipfile`), Python library dependencies (`setup.py`), environment-specific lists (e.g. `requirements/prod.txt`), as well as other languages (e.g. Ruby)

Options
-------

It accepts a user-provided path to a local target project directory; by default it returns information on the project dependencies, including package name, version, current upstream version, and count of any CVEs. There are several flags to modify script behavior / response:

 * `--help, -h`: Show help message and exit
 * `--path PATH, -p`: Set path to local target project directory
 * `--boolean, -b`: Return a Boolean assessment of the project (`FAIL` if any outdated or vulnerable dependencies; `PASS` if not), designed for use in automated testing
 * `--verbose, -v`: Return CVE details, including CVE ID, summary, and link to details
 * `--version, -V`: Return the script's current version and exit
 * `--check, -c`: Run Dependency Scanner on itself
 
Testing
-------

A sample project (`sample-project.tar`) is included to facilitate testing. It contains 2 outdated dependencies and 2 vulnerable dependencies. (The directory has been archived into a single file to prevent Github's automated vulnerability scanner from flagging it.)

In addition, set the self-check flag (`--check, -c`) to have Dependency Scanner perform a self-diagnostic.

Features To Come
----------------

 * Refactor function to run as a serverless service
 * Add option for users to provide a Github repository web URL as the target project instead of a local directory
 * Expand the number of dependency files supported
 * Expand the number of languages supported
 * Maintain an updated copy of the CVE database and refactor the querying process to permit batching
