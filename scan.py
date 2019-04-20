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
    print "FATAL ERROR: {}".format(msg)
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
    project = "sample-projects/pytrader/" # fixthis >> query this from user
    
    # confirm project directory exists
    if not Path(project).is_dir():
        report('project directory not found')
        
    # loop through possible dependency file names and look for file
    dep_files = ['requirements.txt'] # fixthis >> add support for other framework filenames?
    for dep_file in dep_files:
        deps_list = Path(project + dep_file)
        # fixthis >> clean this up
        if deps_list.exists(): # found it so exit
            break
        else: # didn't find it so blank the variable
            deps_list = ""
    if not deps_list: # no possible file found so return an error
        report('dependency list not found')

    # read dependencies from list
    
    # fixthis
    r = requests.get("http://cve.circl.lu/api/cvefor/BeautifulSoup")
    if r.status_code == '200':
        report('API request failed')

    data = json.loads(r.text)
    print data
    report('stopped')
    
    
    with open(str(deps_list)) as lines: # open the file
        for line in lines: # loop through it line-by-line, processing as we go (more memory efficient)
            data = parse_dep(line)
            
            # fixthis >> does CVE API support batch queries? would be more efficient (fewer calls)
            
                
    # output results
    print 'done' # fixthis
    
if __name__ == '__main__':
    __main__()
