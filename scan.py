#!/usr/bin/python

#####################################################
# DEPENDENCIES
#################################n####################

import sys
import json
import argparse
from pathlib import Path
import requests
from packaging.version import parse
from colorama import init, Fore, Style
init(autoreset=True)

#####################################################
# FUNCTIONS
#####################################################

def throw_error(msg):
    """ Output error message and stop """
    print(Fore.RED + Style.BRIGHT + "FATAL ERROR!\n{}".format(msg))
    sys.exit()

def determine_project_path(args):
    """ Determine and confirm project directory """

    # assign user-provided values locally
    path = args.path
    check = args.check

    # determine what we're checking
    if not path: # no user-provided project path
        if not check: # no self-check flag
            print(Fore.RED + Style.BRIGHT + '')
            throw_error('No path provided. Please provide the path to a local project directory.')

        # set Dependency Scanner project directory as target
        from os.path import dirname, abspath
        path = dirname(abspath(__file__))

    # confirm project directory exists
    if not Path(path).is_dir():
        throw_error('Project directory not found: {}'.format(path))

    return path

def find_dependencies_list(path):
    """ Locate the dependencies list within the project directory """

    # check for common dependency list names
    dep_files = ['requirements.txt'] # fixthis >> add filename here to add support
    for dep_file in dep_files:
        deps_list = Path(path + '/' + dep_file)
        if deps_list.exists(): # found it so move on
            break
        deps_list = "" # not found, so blank this variable

    # if no dependency file found return an error
    if not deps_list:
        throw_error('No supported dependency list found')

    return deps_list

def get_current_stable(package):
    """ Determine the current stable upstream version for a given package """

    # request package release data from Pypi
    r = requests.get("https://pypi.python.org/pypi/" + package + "/json")
    if r.status_code != 200:
        throw_error('Pypi API request failed: {}'.format(package))

    # distill current stable version
    data = json.loads(r.text)
    releases = data.get('releases', [])
    version = parse('0') # default
    for release in releases:
        v = parse(release)
        if not v.is_prerelease:
            version = max(version, v)

    return str(version)

def process_cves(r):
    """ Process CVE data (if any) """

    # check number of CVEs (if any)
    l = len(r)
    if l == 0: # no CVEs so stop
        print(Fore.GREEN + "No CVEs found")
        return

    # CVEs found so output data
    print(Fore.RED + "{} CVE{} found!".format(l, "" if l == 1 else "s"))
    for count, cve in enumerate(r):

        print("\n{}. {}".format(count+1, cve['id']))
        print(cve['summary'])

        # assign severity (based on score)
        score = float(cve['cvss'])
        if score <= 3.9:
            severity = "low"
        elif 4.0 <= score <= 6.9:
            severity = "medium"
        elif 7.0 <= score:
            severity = "high"

        print("Severity: {}".format(severity))

def process_dependencies(deps_list):
    """ Process dependencies from project list """

    with open(str(deps_list)) as lines: # fixthis >> add progress bar

        # loop through file contents and process
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'): # skip blank lines and comments

                # check for inline comments and remove (if found)
                if '#' in line:
                    tmp = line.split('#')
                    line = tmp[0].strip()

                # define package and version
                data = line.split('==')
                package = data[0]
                try: # not all packages come with specific versions so EAFP
                    version = data[1]
                except IndexError: # no version provided so use wild card to check for any CVEs
                    version = "*"
                print(Style.BRIGHT + "\n{} ({})".format(package, version))

                # gather current upstream stable version
                current_stable = get_current_stable(package)
                if current_stable > version and version != "*":
                    print(Fore.YELLOW + "Out of date! Current version: {}".format(current_stable))
                else:
                    print(Fore.GREEN + "Version is up to date")

                # check for CVEs
                r = requests.get("https://cve.circl.lu/api/cvefor/cpe:2.3:a:python:" + package + ":" + version)
                if r.status_code != 200:
                    throw_error('API request failed: {}/{}'.format(package, version))

                # process CVE data (if any)
                process_cves(r.json())


#####################################################
# MAIN FUNCTION
#####################################################

def __main__():

    print("Starting scan...")

    # configure command-line options
    parser = argparse.ArgumentParser(prog="Dependency Scanner", description="Scan a project for outdated or vulnerable dependencies")
    parser.add_argument('--path', '-p', help='local path to target project directory')
    parser.add_argument('--boolean', '-b', action="store_true", help="return Boolean assessment (for automated testing)") # fixthis >> add
    parser.add_argument('--version', '-V', action="version", version='%(prog)s 0.1')
    parser.add_argument('--check', '-c', action="store_true", help="run %(prog)s on itself (self-check)")

    # parse user-provided input
    args = parser.parse_args()
    boolean = args.boolean

    # determine target path
    path = determine_project_path(args)

    # find dependency list within project directory
    deps_list = find_dependencies_list(path)

    # process dependencies within list
    process_dependencies(deps_list)

    print('done') # fixthis

if __name__ == '__main__':
    __main__()
