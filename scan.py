#!/usr/bin/python

#####################################################
# DEPENDENCIES
#################################n####################

import sys # for system calls, like exit()
from pathlib import Path # for determining if directories or files exist
import requests # for making HTTP requests to API
import json # for parsing JSON returned from API call
from packaging.version import parse # used in parsing the current stable version from Pypi
from colorama import init, Fore, Back, Style # to provide colored output in terminal
init(autoreset=True)
import argparse # for parsing command-line arguments

#####################################################
# FUNCTIONS
#####################################################

# stop process with error
def throw_error(msg):
    print(Fore.RED + Style.BRIGHT + "FATAL ERROR: {}".format(msg))
    sys.exit()

# prompt user to select project directory
def get_project():
    print(Fore.BLUE + "To start the dependency scan, please select the project directory in the popup dialog.") # fixthis
    Tk().withdraw()
    project = askdirectory()
    project = ""
    if not project:
        throw_error("no project directory indicated")
    elif not Path(project).is_dir():
        throw_error('project directory not found')
    return project

def find_dependencies_list(project):
    dep_files = ['requirements.txt'] # fixthis >> add support for other framework filenames?
    for dep_file in dep_files:
        deps_list = Path(project + dep_file)
        # fixthis >> clean this up
        if deps_list.exists(): # found it so exit
            platform = "python" # fixthis >> add support for other platforms (e.g. Ruby)
            break
        deps_list = "" # we blank deps_list so we'll know when we've run through the entire list unsuccessfully

    # if no dependency file found return an error
    if not deps_list:
        throw_error('dependency list not found')
    

# determine current stable version
def get_current_stable(package):
    
    # request package release data from Pypi
    r = requests.get("https://pypi.python.org/pypi/" + package + "/json")
    if r.status_code != 200:
        throw_error('Pypi API request failed: {}'.format(package))
    
    # distill current stable version
    data = json.loads(r.text)
    releases = data.get('releases', [])
    version = parse('0')
    for release in releases:
        v = parse(release)
        if not v.is_prerelease:
            version = max(version, v)
    return version
    
# process CVEs (if any)
def process_cves(r):
    
    cve_data = [] # array to contain cve data
    for cve in r.json():
        
        # define id and details link
        cve_id = cve['id'] # fixthis >> link to CVE details: cve_lookup_url + cve['id']

        # assign severity (based on score)
        score = float(cve['cvss']) # we float the value because sometimes it comes through as a string
        if score <= 3.9:
            severity = "low"
        elif 4.0 <= score <= 6.9:
            severity = "medium"
        elif 7.0 <= score:
            severity = "high"

        # add cve data
        cve_data.append({
            'cve_id': cve_id,
            'score': score,
            'severity': severity
        })
        
    return cve_data    
    
#####################################################
# MAIN FUNCTION
#####################################################

def __main__():
    
    # configure command-line options
    parser = argparse.ArgumentParser(prog="Dependency Scanner", description="Scan a project for outdated or vulnerable dependencies")

    # local path to project directory
    parser.add_argument('--path', '-p', help='local path to target project directory')

    # return Boolean value (for integration into automated tests) vs details (default=False)
    parser.add_argument('--boolean', '-b', action="store_true", help="return Boolean assessment (for automated testing)")

    # strict mode - flag error on outdated packages (default=False)
    parser.add_argument('--strict', '-s', action="store_true", help="flag outdated dependencies as critical issue")

    # verbose output (default=False)
    parser.add_argument('--verbose', '-v', action="store_true", help="verbose output")
    
    # output current version
    parser.add_argument('--version', '-V', action="version", version='%(prog)s 0.1')
    
    # self-check dependencies
    parser.add_argument('--check', '-c', action="store_true", help="run %(prog)s on itself (self-check)")
    
    # parse arguments
    # fixthis >> simpler way of doing?
    args = parser.parse_args()
    project = args.path
    boolean = args.boolean
    strict = args.strict
    verbose = args.verbose
    check = args.check

    # fixthis >> conflict btwn path and check? what do to if both are provided?
    # if path and check, do path
    # check is optional
    # throw error on no path, no check
    
    # determine what we're checking
    if not project: # no user-provided path
        if not check: # no self-check
            throw_error('Please either provide the path to a local project directory or call the "--check" flag to self-check. Use "--help" for more information.')
        
        # set parent directory as project target    
        from os.path import dirname, abspath
        project = dirname(abspath(__file__))
    
    # confirm project directory exists
    if not Path(project).is_dir():
        throw_error('project directory not found')
        
        
    print(project)
    sys.exit()
    # loop through possible dependency file names and look for file
    dep_files = ['requirements.txt'] # fixthis >> add support for other framework filenames?
    for dep_file in dep_files:
        deps_list = Path(project + dep_file)
        # fixthis >> clean this up
        if deps_list.exists(): # found it so exit
            platform = "python" # fixthis >> add support for other platforms (e.g. Ruby)
            break
        deps_list = "" # we blank deps_list so we'll know when we've run through the entire list unsuccessfully

    # if no dependency file found return an error
    if not deps_list:
        throw_error('dependency list not found')

    # loop through dependencies
    with open(str(deps_list)) as lines: # open the file
        for line in lines: # loop through it line-by-line, processing as we go (more memory efficient)
        
            # fixthis >> add code to handle expected, non-relevant sections within "requirement.txt" (like section headers)
        
            # process data
            data = line.strip().split('==') # parse package name and version
            package = data[0]
            
            results.append({'name': package})
            
            try: # not all packages come with specific versions so EAFP
                version = data[1]
            except IndexError: # no version provided so use wild card to check for any CVEs
                version = "*"
                
            # fixthis >> now we have dependency and version currently in use (for output to result)
            print("processing {} (v{})".format(package,version)) # fixthis >> remove
            
            # gather current upstream stable version
            current_stable = get_current_stable(package)

            # check for CVEs
            r = requests.get("https://cve.circl.lu/api/cvefor/cpe:2.3:a:" + platform + ":" + package + ":" + version)
            if r.status_code != 200:
                throw_error('API request failed: {}/{}/{}'.format(platform, package, version))
                
            # process CVEs (if any)
            cve_data = process_cves(r)
            
            print(current_stable)
            print(cve_data)
                
    # output results
    print(results)
    print('done') # fixthis
    
if __name__ == '__main__':
    __main__()
