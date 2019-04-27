#!/usr/bin/env python

#####################################################
# DEPENDENCIES
#####################################################

import sys
import json
import argparse
from pathlib import Path
import requests
from packaging.version import parse
from colorama import init, Fore, Style
init(autoreset=True)

# global defaults
VERBOSE = False
BOOLEAN = False
TOTAL = 0
OUTDATED = 0
VULNERABLE = 0

#####################################################
# FUNCTIONS
#####################################################

def throw_error(msg):
    """ Output error message and stop """
    print(Fore.RED + Style.BRIGHT + "FATAL ERROR\n{}".format(msg))
    sys.exit()

def confirm_project_path(args):
    """ confirm project directory """

    # determine which path to confirmgit status
    path = args.path
    if not path: # no user-provided project path so look for self-check flag
        if not args.check: # no self-check flag
            error = 'No path provided. Please provide the path to a local project directory'
            error += ' or use the "--check" flag to perform a self-check.'
            throw_error(error)

        # set Dependency Scanner project directory as target
        from os.path import dirname, abspath
        path = dirname(abspath(__file__))

    # confirm project directory exists
    if not Path(path).is_dir():
        throw_error('Project directory not found: {}'.format(path))

    return path

def find_dependencies_list(path):
    """ Locate the dependencies list within the project directory """

    # check for common dependency list names in common locations
    dep_files = ['requirements.txt'] # add other common filenames (e.g. Pipfile)
    for dep_file in dep_files:
        deps_list = Path(path + '/' + dep_file)
        if deps_list.exists(): # found it so move on
            break
        deps_list = "" # not found, so reset

    # if no dependency file found throw an error
    if not deps_list:
        throw_error('No supported dependency list found in project directory')

    return deps_list

def get_data(url):
    """ Make API request and return the data """

    request = requests.get(url)
    if request.status_code != 200:
        throw_error('API request failed: {}'.format(url))

    return request

def get_upstream(package):
    """ Determine the current stable upstream version for a given package """

    # query package release data from Pypi
    upstream_data = get_data("https://pypi.python.org/pypi/{}/json".format(package))
    '''
    upstream_request = requests.get("https://pypi.python.org/pypi/" + package + "/json")
    if upstream_request.status_code != 200:
        throw_error('Pypi API request failed: {}'.format(package))
    '''

    # distill current stable version
    data = json.loads(upstream_data.text)
    releases = data.get('releases', [])
    version = parse('0') # default
    for release in releases:
        test = parse(release)
        if not test.is_prerelease:
            version = max(version, test)

    return str(version)

def process_cves(cves):
    """ Process CVE data (if any) """

    # check number of CVEs (if any)
    length = len(cves)
    if length == 0: # no CVEs so stop
        print(Fore.GREEN + "No CVEs found")
        return 0

    # CVEs found so output data
    print(Style.BRIGHT + Fore.RED + "{} CVE{} FOUND".format(length, "" if length == 1 else "s"))
    if VERBOSE:

        for count, cve in enumerate(cves):

            print("\n{}. {}".format(count+1, cve['id']))
            print(cve['summary'])
            print("https://www.cvedetails.com/cve/{}/".format(cve['id']))

            # assign severity (based on score)
            score = float(cve['cvss'])
            if score <= 3.9:
                severity = "low"
            elif 4.0 <= score <= 6.9:
                severity = "medium"
            elif score >= 7.0:
                severity = "high"

            print("Severity: {}".format(severity))

    return length

def process_dependencies(deps_list):
    """ Process dependencies from project list """

    global TOTAL, OUTDATED, VULNERABLE
    with open(str(deps_list)) as lines: # fixthis >> add progress bar

        # loop through file contents and process
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'): # skip blank lines and comments

                # prune off inline comments (if any)
                if '#' in line:
                    tmp = line.split('#')
                    line = tmp[0].strip()

                # define package and version
                TOTAL += 1
                data = line.split('==')
                package = data[0]
                try: # not all packages come with specific versions so EAFP
                    version = data[1]
                except IndexError: # no version provided so check for any CVEs
                    version = "*"
                print(Style.BRIGHT + "\n{} ({})".format(package, version))

                # gather current stable upstream version
                upstream = get_upstream(package)
                if upstream > version and version != "*":
                    OUTDATED += 1
                    print(Style.BRIGHT + Fore.YELLOW + "OUT OF DATE - Current version is {}".format(upstream))
                else:
                    print(Fore.GREEN + "Version is up to date")

                # check for CVEs
                cve_data = get_data("https://cve.circl.lu/api/cvefor/cpe:2.3:a:python:{}:{}".format(package, version))
                '''''
                cve_request = requests.get()
                if cve_request.status_code != 200:
                    throw_error('API request failed: {}/{}'.format(package, version))
                '''

                # process CVE data (if any)
                vulnerable_deps = process_cves(cve_data.json())
                if vulnerable_deps is not None:
                    VULNERABLE += vulnerable_deps

#####################################################
# MAIN MODULE
#####################################################

def __main__():

    # configure command-line options
    parser = argparse.ArgumentParser(prog="Dependency Scanner", description="Scan a project for outdated or vulnerable dependencies")
    parser.add_argument('--path', '-p', help='Local path to target project directory')
    parser.add_argument('--boolean', '-b', action="store_true", help="Return Boolean assessment (for automated testing)") # fixthis >> add
    parser.add_argument('--verbose', '-v', action="store_true", help="Return CVE details (if any)")
    parser.add_argument('--version', '-V', action="version", version='%(prog)s 0.1')
    parser.add_argument('--check', '-c', action="store_true", help="Run %(prog)s on itself (self-check)")

    # parse user-provided input
    args = parser.parse_args()
    global VERBOSE, BOOLEAN
    VERBOSE = args.verbose
    BOOLEAN = args.boolean

    # start scan
    print("\nStarting {}...".format("self-check" if VERBOSE else "scan"))

    # confirm target path
    path = confirm_project_path(args)

    # find dependency list within project directory
    deps_list = find_dependencies_list(path)

    #fixthis >> good to here

    # process dependencies within list
    process_dependencies(deps_list)

    # compile summary
    # fixthis >> clean this up
    print(Style.BRIGHT + '\nScan complete')
    print("{} dependenc{} scanned".format(TOTAL, "y" if TOTAL == 1 else "ies"))
    # fixthis >> add percentages?
    if OUTDATED:
        print(Style.BRIGHT + Fore.YELLOW + '{} outdated dependenc{}'.format(OUTDATED, "y" if OUTDATED == 1 else "ies"))
    else:
        print(Fore.GREEN + "0 outdated dependencies")
    if VULNERABLE:
        print(Style.BRIGHT + Fore.RED + '{} vulnerable dependenc{}'.format(VULNERABLE, "y" if VULNERABLE == 1 else "ies"))
    else:
        print(Fore.GREEN + "0 vulnerable dependencies\n\n")

if __name__ == '__main__':
    __main__()
