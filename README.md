Dependency Scanner
==================

This function gathers all the dependencies of a project, checks them against Circl's [CVE Search API](https://www.circl.lu/services/cve-search/#public-web-api-of-cve-search), and returns which (if any) have vulnerabilities.

Specific tasks
--------------

This function needs accomplish the following specific tasks:

 1. Obtain all dependencies for the specified project on the local machine.
 2. For each dependency, determine:
  * current version used by the project
  * latest upstream version
  * if there are any Common Vulnerabilities and Exposures (CVEs) affecting the current version of the dependency
 3. Return the data in a manner that communicates the issue we're trying to solve:
  * what dependencies (and version) are in use
  * whether any of these dependencies are out of date (a more recent version exists)
  * whether any of these dependencies contain a known CVE
  
Additional Considerations
-------------------------

 1. How would this function be scaled to dozens or hundreds of repositories?
    * to come
 2. How would I automate this script and track progress over time?
    * Automate: Refactor this function as a dependency and add to a commit pipeline?
    * Track progress: Create an account based on the user that records the results per project
 3. How would this function be integrated into a CI / CD pipeline?
    * See 2a above

Caveats & Assumptions
---------------------

 * currently only configured to scan Python projects

Features To Come
----------------

 * refactor function to be a serverless service (S3 static site > API Gateway > Lambda function > SQS > S3 static site)
 * add option for user to provide Github web URL for a project to be scanned (instead of local download)
 * return the number of CVEs per dependency and the severity
 * for non-supported frameworks, read dependencies right out of `/vendor` subdirectory?
 * expand the number of frameworks supported
   * pipenv: Pipfile.lock, Pipfile
   * Ruby: Gemfile.lock, Gemfile
 * replace current API with one that supports batch requests
   * alternately, download all CVE data then make queries locally (particularly for large dependency sets)

Supported Framework Dependency Lists
--------------------------

 * Python: requirements.txt
 * fixthis >> add more Python-specific list locations / names
 * fixthis >> ultimately add support for other platforms (e.g. Ruby)

Logic Flow
----------

 1. Look for dependency file (e.g. requirements.txt)
 2. Filter dependencies from list
 3. For each dependency:
    1. determine latest upstream version
    2. determine whether CVEs exist for current version
    3. add data to results
 4. Return results in logical, easy to understand format
 
Cases
-----
 
 * project with no dependency list or in a non-supported framework
 * project with no dependencies
 * project with only good dependencies
 * project with vulnerable dependencies
   * https://github.com/rubik/pytrader
   * https://github.com/tanema/vlc-clickr