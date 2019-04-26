#!/usr/bin/python

#####################################################
# DEPENDENCIES
#################################n####################

import sys # for system calls, like exit()
import argparse # for parsing command-line arguments
from pathlib import Path # for determining if directories and/or files exist
import requests # for making HTTP requests to API
import json # for parsing JSON
from packaging.version import parse # used in parsing the current stable version from Pypi
from colorama import init, Fore, Back, Style # to provide cross-platform support for colored output in terminal
init(autoreset=True)

#####################################################
# FUNCTIONS
#####################################################

# output error message and stop
def throw_error(msg):
    print(Fore.RED + Style.BRIGHT + "FATAL ERROR!\n{}".format(msg))
    sys.exit()

# determine and confirm project directory
def determine_project_path(args):
    
    # assign user-provided values locally
    path = args.path
    check = args.check
    
    # determine what we're checking
    if not path: # no user-provided project path
        if not check: # no self-check flag
            throw_error('Please either provide the path to a local project directory or call the "--check" flag to perform a self-check. Use "--help" for more information.')
        
        # set Dependency Scanner project directory as target    
        from os.path import dirname, abspath
        path = dirname(abspath(__file__))
    
    # confirm project directory exists
    if not Path(path).is_dir():
        throw_error('Project directory not found: {}'.format(path))
        
    return path

# locate the dependencies list within the project directory
def find_dependencies_list(path):
    
    # fixthis >> add support for different requirements files for multiple environment within /requirements directory

    ''' Note:
    This function currently only has support for the most common dependency list filename, in the expected location.
    Future updates will include support for Pipfile (from Pipenv), library dependencies (/setup.py), and environment-specific
    dependency lists (/requirements/prod.txt, /requirements/dev.txt, etc).
    '''

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
    elif not dep_file is 'requirements.txt':
        throw_error('This file format is not yet supported: {}'.format(dep_file))

    return deps_list
    
# determine current stable version
def get_current_stable(package):
    
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
    
# process CVEs (if any)
def process_cves(r):
    
    cve_data = [] # array to contain cve data
    for cve in r.json():
        
        # define CVE details
        cve_id = cve['id']
        cve_summary = cve['summary']

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
            'cve_summary': cve_summary,
            'score': score,
            'severity': severity
        })
        
    return cve_data    

# process dependencies
def process_dependencies(deps_list):
    
    results = []
    with open(str(deps_list)) as lines:
    
        # loop through file contents and process
        for line in lines:
            line = line.strip()
            if len(line) > 0 and not line.startswith('#'): # skip blank lines and comments

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
                print("\nProcessing {} {}".format(package,version)) # fixthis >> remove
                
                # gather current upstream stable version
                current_stable = get_current_stable(package)
                # fixthis >> add strict checking to flag outdated packages as critical issues
                '''
                if strict: # strict mode so flag outdated packages as critical issues
                    if parse(current_stable) > parse(version):
                        print('ISSUE: version outdated!')
                '''
                
                # check for CVEs
                r = requests.get("https://cve.circl.lu/api/cvefor/cpe:2.3:a:python:" + package + ":" + version)
                if r.status_code != 200:
                    throw_error('API request failed: {}/{}'.format(package, version))
                
                # gather CVE data (if any)
                cve_data = process_cves(r)
                
                # add to results
                results.append({
                    'package':          package,
                    'version':          version,
                    'current_stable':   current_stable,
                    'cve':              cve_data
                })
                
    return results
    
#####################################################
# MAIN FUNCTION
#####################################################

def __main__():
    
    # configure command-line options
    parser = argparse.ArgumentParser(prog="Dependency Scanner", description="Scan a project for outdated or vulnerable dependencies")
    parser.add_argument('--path', '-p', help='local path to target project directory')
    parser.add_argument('--boolean', '-b', action="store_true", help="return Boolean assessment (for automated testing)") # fixthis >> add
    parser.add_argument('--strict', '-s', action="store_true", help="flag outdated dependencies as critical issue") # fixthis >> add
    parser.add_argument('--version', '-V', action="version", version='%(prog)s 0.1')
    parser.add_argument('--check', '-c', action="store_true", help="run %(prog)s on itself (self-check)")
    
    # parse arguments
    # fixthis >> simpler way of doing?
    args = parser.parse_args()
    boolean = args.boolean
    strict = args.strict
        
    # determine target path
    path = determine_project_path(args)

    # find dependency list within project directory
    deps_list = find_dependencies_list(path)
    
    # process dependencies within list
    results = process_dependencies(deps_list)
            
    # output results
    for r in results:
        print(r['package'])
    
    print('done') # fixthis
    
if __name__ == '__main__':
    __main__()
