
# Author: Jerry Craft
# October 21, 2022
#
# KitchenSink.py -- Everything and the kitchen sink for Nessus files.

# This program is an all around clean up tool I am designing to help me with my
# penetration testing problems.  This tool is surrounded around the idea that Tenable Nessus Pro
# while doing a good job at vunlerability scanning, fails to provide me with reasonable reporting
# mechanisms.  So this tool will make up for the several shortcomings by slicing, dicing, and manipulating
# data from Tenable Nessus CSV files.  This tool will keep me in the console so I can find vulnerabilities
# and exploit them from the same console.

# BEST IF RUN ON KALI LINUX.  SEARCHSPLOIT DATABASES NEED TO BE INSTALLED ON THE COMPUTER RUNNING THIS FILE.

# libraries                             # anything with a *** are libraries that were outside of class.
import os                               # os access
import sys                              # printing to a file
import csv                              # read csv files
import re                               # search expressions
import argparse                         # commandline argument parser ***
import requests                         # grab robots.txt and other text, html files.
from tqdm import tqdm                   # progress bar for longer processes ***

# Argument Parser
# This sets up our arguments and help/options for the user
# discovered argparse: https://towardsdatascience.com/a-simple-guide-to-command-line-arguments-with-argparse-6824c30ab1c3

parser = argparse.ArgumentParser(
        prog='kitchensink.py',
        description='This program is a Nessus Pro CSV Parser.',
        epilog='Compiled for Python 3.9. The libraries needed are: os, sys, csv, re, argparse, requests, tqdm, matplotlib, searchsploit ' +
        '[https://github.com/andreafioraldi/cve_searchsploit]')

parser.add_argument("filename", type=str, help='The [filename] of CSV to read and display.  These are the results you want.')
parser.add_argument('-bar', '--sBar', action='store_true', default=False, help='Generate a stacked barchart on the results of a TOPTEN type search only')
parser.add_argument('-c', '--cAttack', action='store_true', default=False, help='Automatically create attack files and store in all output formats.')
parser.add_argument('-download', '--download', type=str, default='robots.txt', help='Download a file, and list the filename to name the file after its been downloaded [ex. -d robots.txt].  Text file only.')
parser.add_argument('-f', '--field', type=str, default='host', help='The field to search for in the data set [-s Risk]')
parser.add_argument('-graph', '--cGraphics', action='store_true', default=False, help='Create a graph of the vulnerability risks for any search.  Run a search and use [-g] at the end.')
parser.add_argument('-hbar', '--hBar', action='store_true', default=False, help='Generate a horizontal stacked barchart on the results of a TOPTEN type search only')
parser.add_argument('-ip', '--iPrint', action ='store_true', default=False, help='Print a file of the IP addresses of a search.  Run a search and put [-p] at the end')
parser.add_argument('-merge', '--cMerge', type=str, help='Merge two Nessus CSV files together.  [kitchensink.py test.csv -m second.csv] the merged file will be new-merged-csv.csv')
parser.add_argument('-print', '--aPrint', action='store_true', default=False, help='Print search output to a file.  Run grep/awk on this file to pull data as necessary')
parser.add_argument('-q', '--query', action='store_true', default=False, help='Expand the information on a particular finding. SEARCH field cannot be a wildcard ![-s .]!. It must be a specific search.')
parser.add_argument('-s', '--search', type=str, default='.', help='search term to use [ -s Critical].  [ a period . is a wildcard for all]')
parser.add_argument('-sum', '--summary', type=str,  default=False, help='List all types of vulnability names discovered.  This is a simple list to aid in searching data.  Use: [ -sum Name ]')
parser.add_argument('-top', '--topTen', type=int, default=False, help='Generate a top 10 list of systems, and risks.  using [ -b ] together will generate a stacked bar chart.')
parser.add_argument('-w', '--webScrap', action='store_true', default=False, help='WebScrape to a file. Example [robots.txt]')
parser.add_argument('-x', '--eXploit', action='store_true', default=False, help='Run SearchSploit to find an exploit based upon a list of CVEs searched.')
#args = parser.parse_args()

# comment these out when not debugging.
filename = 'test.csv' 
aCtion = False
cAttack = False
download = None
field = 'name'
cGraphics = False
iPrint = False
cMerge = None
aPrint = False
query = False
search = '.'
summary = False
topTen = 50
webScrap = False
eXploit = False
sBar = False
hBar = True
lUsers = None


#global variables
original_stdout = sys.stdout # grab a copy of standard out now before we do any console prints.

############################################################
# open files function
def openFile(filename:str) -> list:
    "Open a nessus.csv file for fields, and rows."
    try: # open our file.
        with open(filename, 'r') as csvfile:
            # open the file and grab header from csv
            csvreader = csv.reader(csvfile)
            fields = next(csvreader)
            rows = [row for row in csvreader]
    # error handling for file mishaps.
    except csv.Error as err:
        print(f'\nError in reading the CSV file.  Check your file.\n\n')
    except IOError as err:
        print(f'\nFilename of the Nessus Pro CSV mandatory, file not found.\n\n')

    return fields, rows
############################################################

def findFields(fields:list, search:str) -> int:
    "Find the fields we are searching."

    for field in fields:
        if (search.lower() == field.lower()) or re.search(search.lower(), field.lower()):
            index = fields.index(field)

    # Did something come up during the field search.
    if index == 0:
        print("No field found, exception found.")
        sys.exit()
    return index

############################################################
def rowInRows(lst:list, index:int) -> list:
    "A basic function to build a list based upon an index/value"
    newLst = []
    for rows in lst:
        if rows[index] not in newLst:
            newLst.append(rows[index])
    # return the new list we found based upon our search
    return newLst
############################################################

def findResults(fields:list, lst:list, fcat:str, search:str) -> list:
    "universal field search feature, tell me the field, and the string, and I will find it"
    result = [] # this is the results from the search.
    ipLst = [] # this is our IP list for the quantity figures.

    try: # check for a valid field for our search.
        # search for our field and return the index
        index = findFields(fields, search)

        # build list for our result [List Comprehension decision for experiment]
        result = [rows for rows in lst
                    if (rows[index].lower() == fcat.lower()) or (re.search(fcat.lower(), rows[index].lower()))]

               # sort key lambda JDP and https://blogboard.io/blog/knowledge/python-sorted-lambda/
        result.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk
        # gather up the ip addresses for our count
        ipLst = rowInRows(lst, 4)

        # raise error if nothing is returnable.
        if len(result) == 0:
            raise ValueError

    # error handling for invalid searches.
    except BaseException as err:
        print(f'\n\n[-] Invalid Search, the options you have chosen are invalid.  {err}')

    return result, ipLst
#############################################################

#############################################################
def printIP(lst:list)-> None:
    "Print a file "
    uniqueList = []
    # open our file for printing.
    printfile = open('ip-address-output.txt', 'w')
    # add unique ip addresses to a new list
    uniqueList = rowInRows(lst, 4)
    # sort the new list
    uniqueList.sort()
    # print IP addresses into a file.
    for item in uniqueList:
        print('{:<15s} '.format(item), file= printfile)
    # close printfile
    printfile.close()
    print('IP addresses printed...')
#############################################################

def printList(fields:list, lst:list, ipLst) -> None:
    "Handle the printing of lists by using column format printing"
    # Turn on printing if necessary
    if aPrint == True:
        print('Printing to file: sink-output.txt')
        turnOnPrint('sink-output.txt')

    # printing in columns: https://scientificallysound.org/2016/10/17/python-print3/
    for rows in lst:
        print('[+] {:<15s} {:<7s} {:<10} {:<10} {:<15} {:.70}'.format(rows[4], rows[6], rows[5], rows[3], rows[1], rows[7]))
    print('---------------------------------------------------------------------------------------------------------')
    print('[=] {:<15s} {:<7s} {:<10} {:<10} {:<15} {:<20}'.format(fields[4], fields[6], fields[5], fields[3], fields[1], fields[7]))
    print("\nTotal Entries: ", len(lst)) # print record count
    print("Total IP Addresses in the list: ", len(ipLst))

    # make a printout of the core main calcs so you can see if critical/highs exist and should be examined.
    crit, high, med, low, non = calcRisk(lst, 'all')
    print(f'Risk Criteria: [Criticals: {crit}, Highs: {high}, Mediums, {med}, Lows: {low}, None: {non}]\n')
    print("Searchable Fields: ", fields, end= '\n\n')

    # Turn off printing
    if aPrint == True:
        turnOffPrint() # turn off printing
        print('Printing done...\n\n')

################################################################

def pQuery(lst:list) -> None:
    #declare
    ipLst = []
    portLst = []
    # roll through the list and build ip list and port list.
    for rows in lst:
        # gather IP addresses and put into a string
        if rows[4] not in ipLst:
            ipLst.append(rows[4])
        # gather ports as well.
        if rows[6] not in portLst:
            portLst.append(rows[6])

    # print the last record of the name info, and add all the IP's/ports affected by that issue.
    # I don't want a scrolling screen of data, rather just a single example, 
    # thus the indenting is on purpose
    print('-------------------------------------------------------------------')
    print(f'[+] Name: {rows[7]}')
    print(f'[+] Ports        : ', portLst)
    print(f'[+] CVE          : ', rows[1])
    print(f'[+] CVE Base     : ', rows[3])
    print(f'[+] Risk Level   : ', rows[3])
    print('-------------------------------------------------------------------')
    print(f'[+] Synopsis: ', rows[8])
    print(f'\n[+] Description: ', rows[9])
    print(f'\n[+] Plugin Output: ', rows[12])
    print(f'\n[+] Solution:', rows[10])
    print(f'\n[+] See also  :', rows[11])
    print('-------------------------------------------------------------------')
    print(f'[+] IP Addresses :', ipLst)
    print('\n\n\n')

################################################################

def attackFiles(lst:list) -> None:
    "Gather Eyewitness data / nikto data and create attack files"
    # look for directories and if not there, make them.
    niktodir = 'nikto'
    eyewitnessdir = 'eyewitness'

    # create directories for the data.
    for i in (niktodir, eyewitnessdir):
        isExist = os.path.exists(i)
        if not isExist:
            os.makedirs(i)

    # create our files, directories, and data elements.
    with open("eyewitness/eyewitness.txt", 'w') as fp:
        with open("nikto/nikto.sh", 'w') as np:
           # open files so we can write attack files.
                for rows in lst:  # write all at once.
                    if re.search("HTTP Server", rows[7]):
                        eyewitness = "http://" + rows[4] + ":" + rows[6] + "\n"
                        niktoitem = "nikto -h " + rows[4] + ":" + rows[6] + " -o " + rows[4] + "-" + rows[6] + ".txt" + "\n"
                        fp.write(eyewitness)
                        np.write(niktoitem)

    # print user message
    print("files created...\n\n")
    print('Go into each directory, and execute the files using normal sh command structure, or use the underlying scripts [eyewitness].')
    print('Run each .sh file as a job task in Linux')
    print('[ nohup sh nikto.sh & ] then watch the nohup.log file for details. ')
    print('Run eyewitness using [ eyewitness -f eyewitness.txt ]')

#####################################################################

def calcRisk(lst:list, item:str) -> int:
    """ Generate risk figures for detailed data points """
    # create counters
    ccounter = 0
    hcounter = 0
    mcounter = 0
    lcounter = 0
    ncounter = 0
    newLst = []

    # build a list for the plot graph [LC]
    if item != 'all':
        newLst = [rows for rows in lst if (rows[4] == item)]

    # if plot, do first, if plot do last.
    if item != 'all':
        for rows in newLst: # calc special list
            ccounter += rows[3].count('Critical')
            hcounter += rows[3].count('High')
            mcounter += rows[3].count('Medium')
            lcounter += rows[3].count('Low')
            ncounter += rows[3].count('None')
    else:
        for rows in lst: # calc whole list
            ccounter += rows[3].count('Critical')
            hcounter += rows[3].count('High')
            mcounter += rows[3].count('Medium')
            lcounter += rows[3].count('Low')
            ncounter += rows[3].count('None')

    return ccounter, hcounter, mcounter, lcounter, ncounter
#############################################################

def riskGraph(crit:int,high:int,med:int,low:int) -> None:
    "Create a graph using the risk points."
    # I only want to see the graphing message if we choose to graph. No reason to run everytime.
    import matplotlib.pyplot as plt  # Turn on if were graphing only.  Don't turn on globally
    # learned alot in class, but here: https://www.geeksforgeeks.org/bar-plot-in-matplotlib/

    # count the values for each item.
    # gather keys and values
    keys = ['Critical:' + str(crit), 'High:' + str(high), 'Medium:' + str(med), 'Low:' + str(low)]
    values = [crit, high, med, low]
    answer = "Total Risks Found: " + str(crit + high + med + low)

    # setup color values
    # RGB from W3Schools: https://www.w3schools.com/python/matplotlib_bars.asp
    c = ['#cc0000', '#ff8300', '#ffcf00', '#0000d4']

    # plot graph
    plt.bar(keys, values, align='center', color=c) # build chart
    plt.xticks(range(len(values)), keys)
    plt.xlabel(answer)
    plt.title("Vulnerabilities by Risk") # make pretty

    plt.show()
######################################################

def get_pages(url) -> str:
    "Grab webpages or robots, etc."
    # grab the web pages, and text.
    webpage = requests.get(url)
    webtext = webpage.text

    return webtext
#######################################################

def requestPage(lst:list, req:str) -> None:
    "Function to go thorugh and return different URL's for Soup."
    # send beginning url to loop, and print to file an object

    for rows in lst:
        url = 'http://' + rows[4] + ':' + rows[6]
        # choose robots or other file
        send = url + "/" + req
        fil = rows[4] + req

        turnOnPrint(fil + '.txt') # turn on console printing
        print(get_pages(send)) # grab a robot file.
        turnOffPrint() # turn off std print.
#######################################################

def turnOnPrint(fil:str) -> None:
    "Turn on Console Prints"
    # if were printing then set stdout to a file.
    # (https://www.delftstack.com/howto/python/python-output-to-file/)

    original_stdout = sys.stdout  # save original stdout
    sys.stdout = open(fil, 'w') # write file
#########################################################

def turnOffPrint()-> None:
    "Turn off stdout back to original for Console Print off"
    # set stdout back
    sys.stdout = original_stdout
##########################################################

def merge(lst:list, fil:str)-> None:
    'Merge two different csv files together.'
    # go get our data to merge.
    fields, lst2 = openFile(fil) # go get the second file and return a list

    # extend the first list with the second one.
    lst.extend(lst2) # https://www.w3schools.com/python/gloss_python_join_lists.asp
    print(f'Merging: {filename} and {fil} into a new file called new-merged-csv.csv')

    ## Save the merged file into a new file so we don't destroy original.
    with open('new-merged-csv.csv', 'w', newline='') as f: #
        write = csv.writer(f) # https://stackoverflow.com/questions/3348460/csv-file-written-with-python-has-blank-lines-between-each-row
        write.writerow(fields) #https://www.geeksforgeeks.org/python-save-list-to-csv/
        write.writerows(lst)
    print('Finished writing CSV file: new-merged-csv.csv.  Old file preserved.\n\n')

##############################################################

def stakBar(lst:list) -> None:
    "Generate a stacked bar chart to help understand results"
    import matplotlib.pyplot as plt
    crit = 0
    high = 0
    med = 0
    low = 0
    nan = 0
    newLst = []
    # run through our list, and build our graph.
    for rows in lst:
        if rows[4] not in newLst:
            # if IP not found in newLst
            crit,high,med,low,nan = calcRisk(lst, rows[4]) # calc risk
            # build the bar
            plt.bar(rows[4], low, color='#0000d4')
            plt.bar(rows[4], med, bottom=low, color='#ffcf00')
            plt.bar(rows[4], high, bottom=low+med, color='#ff8300')
            plt.bar(rows[4], crit, bottom=low+med+high, color='#cc0000')
            # append ip to new list so we don't do it again.
            newLst.append(rows[4])
            # end when were done
    plt.xlabel("IP Addresses")
    plt.ylabel("Risk")
    plt.legend(['Low', 'Medium', 'High', 'Critical'])
    plt.title("Top Systems by Risk")
    plt.show()

###################################################################

def horiBar(lst:list) -> None:
    " Generate a horizonal stacked bar"
    # include here to avoid making the graph text appear
    from matplotlib import pyplot as plt

    # run through our list, and build our graph.
    for rows in lst:
        plt.barh(rows[0], rows[1], align='center')
    plt.title("Top Systems by Risk")

    plt.show()

###################################################################
def riskCalc(ipLst:list, finalLst:list) -> list:
    calcLst = []
    sumRisk = 0
        # now calculate up all the risks for each host to get a top 10
    for ip in tqdm(ipLst, desc='Calc List:'): # run our progressbar so we can see console movement.
        for rows in finalLst:
            if ip in rows:
                if rows[2] != "":
                    sumRisk += float(rows[2])
        calcLst.append([ip, sumRisk])
        sumRisk = 0
    # sort all by risk value and keep top 10 in a list
    calcLst.sort(key= lambda x : x[1], reverse=True)    # return a sorted list by Risk Value

    return calcLst

###################################################################

def topTenIP(lst:list, amt) -> list:
    "Get the top 10 IP addresses from the lst, and then generate a list for those systems with total risk"
    # declare
    topIP = []
    finalLst = []
    calcLst = []
    
    # get a list of host addresses to begin
    topIP = rowInRows(lst, 4)
    # now get a list of all vulnerabilities for these hosts
    fields, rows = openFile(filename)
    #https://medium.com/@harshit4084/track-your-loop-using-tqdm-7-ways-progress-bars-in-python-make-things-easier-fcbbb9233f24
    finalLst = [row for ip in tqdm(topIP, desc="Pull List:") for row in rows if ip == row[4]]

    calcLst = riskCalc(topIP, finalLst)

    del(calcLst[amt:]) # got my top 10.
    # now get those rows that have all the detail for those IP's.
    lst.clear() # reuse lst.
    # [LC] for find the new results
    lst = [rows for ip in calcLst for rows in finalLst if rows[4] == ip[0]]
    # sort our new list
    lst.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk
    printList(fields, lst, calcLst)
    
    # print our new summary
    print(f'Top systems most risky are in order: ')
    for ip in calcLst:
        print('IP: {:<16} : CVE Risk Value: {:.2f}'.format(ip[0], ip[1]))

    # if we are building a graph, go do it.
    if sBar == True:
        stakBar(lst)
    if hBar == True:
        horiBar(calcLst)
    ####################################################

def searchExploit(lst:list) -> None:
    "Search for exploits using Kali version of SearchSploit"
    import cve_searchsploit as cs # load if needed
    resultLst = []

    # first clone exploitdb in case its not available
    cs.update_db()

    # open our file and run through the list printing results.
    exploitFile = open('exploit.txt', 'w')
    for rows in tqdm(lst):  # progress bar as CVE to Exploits are found
        # find each cve as necessary
        if cs.edbid_from_cve(rows[1]) != []:
            if rows[1] not in resultLst: # if CVE has already been seen, move on.
                resultLst.append(rows[1]) # add to list and print
                print(f'CVE: {rows[1]} and Exploit: ', cs.edbid_from_cve(rows[1]), file = exploitFile)

    # Close me.
    exploitFile.close()

#####################################################
def nameSummary(fields:list, lst:list, search:str) -> None:
    "Build and print a list of all vulnerabilities so a quick review can be done."
    newLst = []
    index = findFields(fields, search)

    try:
        # # grab list and start sorting out names into a new list        
        newLst = rowInRows(lst, index)
        # sort my list and print it.
        newLst.sort(key= lambda x : x)
        for row in newLst:
            print('[+]', row)
        print('--------------------------------------------------------')
        print('[=] Field to search = ', fields[index])
        print('[=] Total number of records: ', len(newLst))
        print("\nSearchable Fields: ", fields, end= '\n\n')
        print("\n\n")

    # error handling for invalid searches.
    except BaseException as err:
        print(f'\n\n[-] Invalid Search, the options you have chosen are invalid.  {err}')

#####################################################
def localUsers(fields:list, lst:list, fcat:str) -> None:
    "A module to review the lows for disabled users"
    mainSP = []
    # grab a list of systems that have the synopsis field for users
    newLst, ipLst = findResults(fields, lst, fcat, 'name',) 
    synopLst = rowInRows(newLst, 12)
    for rows in newLst:
        mainSP = rows[12].split('\n')
        for row in mainSP:
            if re.search('^  - ', row) or re.search('^- ', row):
                print(f'IP Address {rows[4]} {row}')
    
    print("\n\nSample Search Strings")
    print('SMB Use Host SID to Enumerate Local Users')
    print("Microsoft Windows SMB Shares Enumeration")
    print("Microsoft Windows - Local Users Information : Never Changed Password")
    print("Windows SMB Shares Unprivileged Access")
    print("Microsoft Windows 'Administrators' Group User List")

#####################################################
# main function
def main():
    #
    #################################################
    # grab the file, and start gathering information
    fields, rows = openFile(filename) # Grab the data from the csv, and return fields + rows in a list
    # go get what we are looking for...
    lst, ipLst = findResults(fields, rows, search, field)  # make into a future switch  -C for Critical -H for High
    # abort if something goes unexpected and returns nothing.
    if len(lst) == 0:
        print('\nSearch returned nothing, check your search and try again.\n')
        sys.exit()
    ################################################

    # Do things based upon arg switches

    # create a top X report
    if topTen != 0:
        print('\n\nGenerating Top list')
        topTenIP(rows, topTen)
        sys.exit()
    # create a summary and print it
    if summary != 0:
        nameSummary(fields, lst, summary)
        sys.exit()
    # create a bar graph of the results
    if cGraphics == True:
        print('Creating graphics...')
        a, b, c, d, e = calcRisk(lst, 'all') # I won't always use e = None
        riskGraph(a,b,c,d)
        sys.exit()
    # merge two files together
    if cMerge != None:
        print('Merging documents')
        merge(lst, cMerge)
        sys.exit()
    # create attack files for nikto, nmap and eyewitness
    if cAttack == True:
        print('Generating files.')
        attackFiles(lst)
        sys.exit()
    # find exploits through searchsploit
    if eXploit == True:
        print('Searching for exploits, check exploit.txt for findings')
        searchExploit(lst)
        sys.exit()
    # web scraping robots and other text files.
    if (webScrap == True) and (download != ""):
        print('running. file download')
        requestPage(lst, download)
    # printing section
    if (search != '.') and (query == True):
        pQuery(lst)
        sys.exit()
    elif(search == '.') and (query == True):
        print('\nYour query failed.  You need to narrow the search to a single name field item to inspect the details.\n\n')
        sys.exit()
    if iPrint == True:
        print('\nPrinting your IP data to a file.')
        printIP(lst)
        sys.exit()
    # stacked bar section
    if sBar == True and topTen == False:
        print('You need to perform a TOP TEN type search [-t 10] to get a stacked barchart.')
        sys.exit()
    if lUsers != None:
        localUsers(fields, lst, lUsers)
        sys.exit()
    
    # otherwise always print this list, either to a file or to the screen.
    printList(fields, lst, ipLst) # print fields, and findings.

    ###############################################

# dunder start
if __name__ == "__main__":
    main()
