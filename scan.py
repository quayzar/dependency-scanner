#!/usr/bin/python

#####################################################
# DEPENDENCIES
#################################n####################

import sys # for system calls, like exit()
from pathlib import Path # for determining if directories or files exist
import requests # for making HTTP requests to API
import json # for parsing JSON returned from API call

#####################################################
# FUNCTIONS
#####################################################

# stop process with error
def report(msg): # fixthis >> remove from prod?
    print("FATAL ERROR: {}".format(msg))
    sys.exit()
    
# return dependency and version (if any)
# fixthis >> modify to support other frameworks than Python
def parse_dep(dep):
    return dep.strip().split('==')

#####################################################
# MAIN FUNCTION
#####################################################

def __main__():
    
    # definitions
    results = [] # array to contain results data
    project = "sample-projects/" # fixthis >> query this from user
    cve_lookup_url = "https://www.cvedetails.com/cve/"
    
    # confirm project directory exists
    if not Path(project).is_dir():
        report('project directory not found')
        
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
        report('dependency list not found')

    # loop through dependencies
    with open(str(deps_list)) as lines: # open the file
        for line in lines: # loop through it line-by-line, processing as we go (more memory efficient)
        
            # fixthis >> add code to handle expected, non-relevant sections within "requirement.txt" (like section headers)
        
            # process data
            data = parse_dep(line)
            package = data[0]
            try: # not all packages come with specific versions so EAFP
                version = data[1]
            except IndexError: # no version provided so use wild card to check for any CVEs
                version = "*"
                
            # fixthis >> now we have dependency and version currently in use (for output to result)
            print("processing {} (v{})".format(package,version)) # fixthis >> remove
            
            # fixthis >> query latest upstream version
            # fixthis >> now we have current upstream version for specific dependency

            # check for CVEs
            r = requests.get("https://cve.circl.lu/api/cvefor/cpe:2.3:a:" + platform + ":" + package + ":" + version)
            if r.status_code != 200:
                report('API request failed')
                
            # process CVEs (if any)
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
                
            print(cve_data)

    '''
    # fixthis >> ultimately process data output and add to result array (apply html, classes, etc)
    data = json.loads(r.text)
    for entry in data:
        print("\nSummary: " + entry['summary'])
        print("CVE: " + entry['id'])
        print("CVS Score: " + str(entry['cvss']))

    sys.exit() # fixthis >> remove
    
    

    '''
                
    # output results
    print('done') # fixthis
    
if __name__ == '__main__':
    __main__()
