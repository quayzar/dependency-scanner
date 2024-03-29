#!/usr/bin/env python
""" Dependency Scanner - Scan a project for outdated or vulnerable dependencies """

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

# set up default parameters
PARAMS = {
    "verbose":      False,
    "boolean":      False,
    "total":        0,
    "outdated":     0,
    "vulnerable":   0
}
RED = Style.BRIGHT + Fore.RED
YELLOW = Style.BRIGHT + Fore.YELLOW
GREEN = Fore.GREEN

#####################################################
# FUNCTIONS
#####################################################

def report(msg):
    """ Output message to console """
    if not PARAMS['boolean']: # boolean output flag not set so print
        print(msg)

def throw_error(msg):
    """ Output error message and stop """
    report(RED + "FATAL ERROR\n{}".format(msg))
    sys.exit()

def make_suffix(field):
    """ Return appropriate suffix based on quantity """
    return "y" if PARAMS[field] == 1 else "ies"

def confirm_project_path(args):
    """ confirm project directory """

    # determine which path to confirm
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
    dep_files = ['requirements.txt'] # add other common filenames here (e.g. Pipfile)
    for dep_file in dep_files:
        deps_list = Path(path + '/' + dep_file)
        if deps_list.exists(): # found it so move on
            return deps_list

    # if no dependency file found throw an error
    throw_error('No supported dependency list found in indicated project directory')
    return False

def get_data(url):
    """ Make API request and return the data (if any) """
    request = requests.get(url)
    if request.status_code != 200:
        throw_error('API request failed: {}'.format(url))
    return request

def get_upstream(package):
    """ Determine the current stable upstream version for a given package """

    # get package release data from Pypi
    upstream_data = get_data("https://pypi.python.org/pypi/{}/json".format(package))

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

    # check for CVEs
    length = len(cves)
    if length == 0: # no CVEs
        report(GREEN + "No CVEs found")
    else: # CVEs found so output data

        PARAMS['vulnerable'] += 1
        report(RED + "{} CVE{} FOUND".format(length, "" if length == 1 else "s"))

        # if verbose flag was passed output CVE details
        if PARAMS['verbose']:
            for count, cve in enumerate(cves):

                # output CVE data
                report("\n{}. {}".format(count+1, cve['id']))
                report("Description: {}".format(cve['summary']))
                report("Link: https://www.cvedetails.com/cve/{}/".format(cve['id']))

                # assign severity (based on score)
                score = float(cve['cvss'])
                if score <= 3.9:
                    severity = "low"
                elif 4.0 <= score <= 6.9:
                    severity = "medium"
                elif score >= 7.0:
                    severity = RED + "high"
                report("Severity: {} ({})".format(severity, cve['cvss']))

def process_dependencies(deps_list):
    """ Process dependencies from project list """

    # loop through file contents and process
    with open(str(deps_list)) as lines:

        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'): # skip blank lines and comments

                # prune off inline comments (if any)
                if '#' in line:
                    tmp = line.split('#')
                    line = tmp[0].strip()

                # define package and version
                PARAMS['total'] += 1
                data = line.split('==')
                package = data[0]
                try: # not all packages come with specific versions so EAFP
                    version = data[1]
                except IndexError: # no version provided so check for any CVEs
                    version = "*"
                report(Style.BRIGHT + "\n{} ({})".format(package, version))

                # gather current stable upstream version
                upstream = get_upstream(package)
                if upstream > version and version != "*":
                    PARAMS['outdated'] += 1
                    report(YELLOW + "OUT OF DATE - Current version is {}".format(upstream))
                else:
                    report(GREEN + "Version is up to date")

                # get CVE data (if any)
                cve_url = "https://cve.circl.lu/api/cvefor/cpe:2.3:a:python:"
                cve_data = get_data(cve_url + package + ":" + version)

                # process CVE data (if any)
                process_cves(cve_data.json())

def output_summary(field):
    """ Compile summary data for given field """

    found = PARAMS[field]
    if found:
        color = YELLOW if field == "outdated" else RED
        suffix = make_suffix(field)
        percent = int(found * 100 / PARAMS['total'])
        report(color + '{} {} dependenc{} ({}%)'.format(found, field, suffix, percent))
    else:
        report(GREEN + "0 {} dependencies".format(field))

#####################################################
# MAIN MODULE
#####################################################

def __main__():

    # configure command-line options
    parser = argparse.ArgumentParser(prog="Dependency Scanner")
    parser.add_argument('--path', '-p', help='Local path to target project directory')
    parser.add_argument('--boolean', '-b', action="store_true", help="Return Boolean assessment")
    parser.add_argument('--verbose', '-v', action="store_true", help="Return CVE details (if any)")
    parser.add_argument('--version', '-V', action="version", version='%(prog)s 0.1')
    parser.add_argument('--check', '-c', action="store_true", help="Run %(prog)s on itself")

    # parse user-provided input and assign
    args = parser.parse_args()
    PARAMS['verbose'] = args.verbose
    PARAMS['boolean'] = args.boolean

    # confirm target path
    path = confirm_project_path(args)
    report("\nStarting {}...".format("scan" if args.path else "self-check"))

    # find dependency list within project directory
    deps_list = find_dependencies_list(path)

    # process dependencies within list
    process_dependencies(deps_list)

    # compile summary
    if PARAMS['boolean']: # return pass / fail
        if PARAMS['outdated'] or PARAMS['vulnerable']: # there were issues so fail
            print("FAIL")
        else: # no issues so pass
            print("PASS")
    else: # return summary
        report(Style.BRIGHT + '\nSUMMARY')
        report("{} dependenc{} scanned".format(PARAMS['total'], make_suffix('total')))
        output_summary('outdated')
        output_summary('vulnerable')
        print('')

if __name__ == '__main__':
    __main__()
