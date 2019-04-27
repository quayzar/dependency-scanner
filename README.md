Dependency Scanner
==================

This script scans a project for outdated or vulnerable dependencies. While it currently only supports Python projects with the default dependency list (`requirements.txt`), it could easily be extended to support other Python-specific dependency lists (e.g. `Pipfile`), Python library dependencies (`setup.py`), environment-specific lists (e.g. `requirements/prod.txt`), as well as other languages (e.g. Ruby)

Options
-------

It accepts a user-provided path to a local target project directory; by default it returns information on the project dependencies, including package name, version, current upstream version, and count of any CVEs. There are several flags to modify script behavior / response:

 * `--help, -h: Show help message and exit
 * `--path PATH, -p: Set path to local target project directory
 * `--boolean, -b`: Return a Boolean assessment of the project (`FAIL` if any outdated or vulnerable dependencies; `PASS` if not), designed for use in automated testing
 * `--verbose, -v`: Return CVE details, including CVE ID, summary, and link to details
 * `--version, -V`: Return the script's current version and exit
 * `--check, -c`: Run Dependency Scanner on itself
 
Sample Projects
---------------

There are two sample projects included with the repository to facilitate testing:

 * sample-projects/example
 * sample-projects/pytrader
 
In addition, set the self-check flag (`--check, -c`) to have Dependency Scanner perform a self-diagnostic.

Features To Come
----------------

 * Refactor function to run as a serverless service
 * Add option for users to provide a Github repository web URL as the target project instead of a local directory
 * Expand the number of dependency files supported
 * Expand the number of languages supported
 * Maintain an updated copy of the CVE database and refactor the querying process to permit batching
 

Additional Considerations
-------------------------

 1. How would this function be scaled to dozens or hundreds of repositories?
    * to come
 2. How would I automate this script and track progress over time?
    * Automate: Refactor this function as a dependency and add to a commit pipeline?
    * Track progress: Create an account based on the user that records the results per project
 3. How would this function be integrated into a CI / CD pipeline?
    * See 2a above


