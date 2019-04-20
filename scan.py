#!/usr/bin/python

#####################################################
# DEPENDENCIES
#################################n####################

import sys # for system calls, like exit()
from pathlib import Path # for determining if directories or files exist

#####################################################
# FUNCTIONS
#####################################################

# stop process with error
def report(msg): # fixthis >> remove from prod?
    print "FATAL ERROR: {}".format(msg)
    sys.exit()

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
        
    # locate dependencies list
    dep_files = ['requirements.txt'] # fixthis >> add support for other frameworks
    for dep_file in dep_files:
        deps_list = Path(project + dep_file)
        if deps_list.exists(): # found it
            print "found {}".format(deps_list)
            # fixthis >> determine file format based on name
        else:
            deps_list = "" # blank this variable so we know if we've run the entire list and found nothing
    if deps_list == "": # fixthis >> replace this ugly way of telling we've not found any file out of all options
        report('deps list not found')

    report(deps_list)

    ''' fixthis
    
    I'm hardcoding this path and filename for now, so I can focus on processing
    the file data and calling the API. This will be replaced with a method to
    a) prompt the user to point to the dependencies list manually (popup)
    b) prompt the user for the project directory, then scan for common file names for supported frameworks (e.g. Python > requirements.txt)
    c) other?
    
    If b) I will also need to iterate through logical alternatives. For example, if 'Gemfile.lock' isn't found, look for 'Gemfile', etc.

    '''
    file = "sample-projects/pytrader/requirements.txt" # fixthis

    # load list of dependencies from list
    
    # load file content
    
    # distill dependencies list
    
    # loop through dependencies
    
    print 'done'
    

    
if __name__ == '__main__':
    __main__()
