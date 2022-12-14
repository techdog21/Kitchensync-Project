
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

# libraries                             
import sys                              # printing to a file
import csv                              # read csv files
import re                               # search expressions
import json                             # save some data as json
import argparse                         # commandline argument parser
import requests                         # grab robots.txt and other text, html files.
from tqdm import tqdm                   # progress bar for longer processes
import subprocess                       # execute local processes
import shodan                           # run shodan API searches
import networkx as nx                   # import network graphing.
from censys.search import CensysHosts   # censys recon API

# Argument Parser
parser = argparse.ArgumentParser(
        prog='kitchensink.py',
        description='This program is a Nessus Pro CSV Parser.',
        epilog='Compiled for Python 3.9. The libraries needed are: os, sys, csv, re, argparse, requests, tqdm, matplotlib, searchsploit ' +
        '[https://github.com/andreafioraldi/cve_searchsploit]')

parser.add_argument("filename", type=str, help='The [filename] of CSV to read and display.  These are the results you want.')
parser.add_argument('-address', '--address', action='store_true', default=False, help='Generate a list of subnets identified')
parser.add_argument('-bar', '--sBar', action='store_true', default=False, help='Generate a stacked barchart on the results of a TOPTEN type search only')
parser.add_argument('-c', '--cAttack', action='store_true', default=False, help='Automatically create attack files and store in all output formats.')
parser.add_argument('-censys', '--censys', action='store_true', default=False, help='Run a Censys search based upon your API connectivity')
parser.add_argument('-download', '--download', type=str, default='robots.txt', help='Download a file, and list the filename to name the file after its been downloaded [ex. -d robots.txt].  Text file only.')
parser.add_argument('-f', '--field', type=str, default='host', help='The field to search for in the data set [-s Risk]')
parser.add_argument('-graph', '--cGraphics', action='store_true', default=False, help='Create a graph of the vulnerability risks for any search.  Run a search and use [-g] at the end.')
parser.add_argument('-ip', '--iPrint', action ='store_true', default=False, help='Print a file of the IP addresses of a search.  Run a search and put [-p] at the end')
parser.add_argument('-bloodhound', '--bloodhound', type=str, default=".", help='Display a list of AD information that Nessus discovered.')
parser.add_argument('-merge', '--cMerge', type=str, help='Merge two Nessus CSV files together.  [kitchensink.py test.csv -m second.csv] the merged file will be new-merged-csv.csv')
parser.add_argument('-print', '--aPrint', action='store_true', default=False, help='Print search output to a file.  Run grep/awk on this file to pull data as necessary')
parser.add_argument('-q', '--query', type=int, default=False, help='Expand the information on a particular finding. SEARCH field cannot be a wildcard ![-s .]!. It must be a specific search.')
parser.add_argument('-s', '--search', type=str, default='.', help='search term to use [ -s Critical].  [ a period . is a wildcard for all]')
parser.add_argument('-shodan', '--shodan', action='store_true', default=False, help='run showdan on IP addresses provided using the Shodan API')
parser.add_argument('-sum', '--summary', type=str,  default=False, help='List all types of vulnability names discovered.  This is a simple list to aid in searching data.  Use: [ -sum Name ]')
parser.add_argument('-top', '--topTen', type=int, default=False, help='Generate a top 10 list of systems, and risks.  using [ -b ] together will generate a stacked bar chart.')
parser.add_argument('-w', '--webScrap', action='store_true', default=False, help='WebScrape to a file. Example [robots.txt]')
parser.add_argument('-x', '--eXploit', action='store_true', default=False, help='Run SearchSploit to find an exploit based upon a list of CVEs searched.')
parser.add_argument('-force', '--force', action='store_true', default=False, help='Make a full listing show.')
args = parser.parse_args()

#global variables
original_stdout = sys.stdout # grab a copy of standard out now before we do any console prints.

def isPrivateAddr(lst:list) -> bool:
    "Check for RFC1918 local addresses"
    for rows in lst:
        if rows[4].startswith("10.") or rows[4].startswith("172.16") or rows[4].startswith("192.168.1"):
            return True
        else:
            return False

def cen(lst:list) -> None:
    "Run a Censys search on the data discovered"
    # run censys config to add your api/secret to the environment
    if isPrivateAddr(lst) == True: print('You cannot run Censys on a private network', sys.exit())
    h = CensysHosts()
    hosts = h.bulk_view(rowInRows(lst, 4))
    json_object = json.dumps(hosts, indent=4)
    # write to json file
    with open('censys.json', 'w') as outfile:
        outfile.write(json_object)
    print('censys.json file written.')

# put together a newtork graph
def networkGraph(lst:list) -> None:
    "Build a network graphic showing the red team attacking the subnets."
    import matplotlib.pyplot as plt
    G = nx.DiGraph()
    G.add_nodes_from(lst)
    # create links to edges.
    for item in lst:
        G.add_edge("Red Team", item)
    nx.draw(G, with_labels=True)
    plt.show()

# Get a list of IP addresses and find subnets
def subnetFinder(lst:list):
    "Get a list, pull all IP's, and build a subnet list for easier scanning"
    ipLst = rowInRows(lst, 4) # get my IP's
    subnetLst = []
    for ip in ipLst:
        item = ip.rsplit('.')
        sub = item[0] + '.' + item[1] + '.' + item[2] + '.0/24'
        if sub not in subnetLst:
            subnetLst.append(sub)
    print('\nSubnets Found', len(subnetLst))
    print('--------------------------------')
    for i in subnetLst: print(i, end='\n') # print line
    print('--------------------------------')
    networkGraph(subnetLst)

# shodan reports ##
def sdan(lst:list)-> list:
    "Go to Shodan and pull IP data from their database"
    finalLst =[] # I do declare
    # read the key file for the shodan api key
    try: 
        f = open('key.txt', 'r')
        SHODAN_API_KEY = f.read()
        api = shodan.Shodan(SHODAN_API_KEY)
    except IOError as err:
        print('Check your key.txt file for your API- shodan=API for the Shodan Service.')

    if args.aPrint == True: 
        print('Printing to a file called shodan.txt') 
        turnOnPrint('shodan.txt')
    # loop through to get IP addresses avoiding RFC 1918 addresses
    for rows in lst:
        if rows[4].startswith("10.") or rows[4].startswith("172.16") or rows[4].startswith("192.168.1"):
            print('You cannot Shodan Internal IP Addresses')
            sys.exit()
        else:
            if rows[4] not in finalLst:
                try:
                    # Search Shodan
                    print (f'------- {rows[4]} -----------------')
                    results = api.host(rows[4])
                    for key, values in results.items():
                        # Show the results
                        if key != 'data':
                            print(key, " : ", values)
                    print(f'------------------------------------\n')
                except shodan.APIError as e:
                    print('Error: {}'.format(e))
                finalLst.append(rows[4]) # don't look twice
    if args.aPrint == True: 
        print('Done printing.') 
        turnOffPrint()

# open files function
def openFile(filename:str) -> list:
    "Open a nessus.csv file for fields, and rows."
    try: # open our file.
        with open(filename, 'r') as csvfile:
            # open the file and grab header from csv
            csvreader = csv.reader(csvfile)
            fields = next(csvreader)
            rows = [row for row in tqdm(csvreader, 'Reading file...')]
    # error handling for file mishaps.
    except BaseException as err:
        print(f'\nFilename of the Nessus Pro CSV mandatory, file not found.\n\n')
        sys.exit(1)
    return fields, rows

def findFields(fields:list, search:str) -> int:
    "Find the fields we are searching."
    for field in fields:
        if (search.lower() == field.lower()) or re.search(search.lower(), field.lower()):
            index = fields.index(field)
            break # find the first match
    # Did something come up during the field search.
    if index == 0:
        print("No field found, exception found.")
        sys.exit()
    return index

def rowInRows(lst:list, index:int) -> list:
    "A basic function to build a list based upon an index/value"
    newLst = []
    for rows in lst:
        if rows[index] not in newLst:
            newLst.append(rows[index])
    # return the new list we found based upon our search
    return newLst

def findResults(fields:list, lst:list, fcat:str, search:str) -> list:
    "universal field search feature, tell me the field, and the string, and I will find it"
    result = [] # this is the results from the search.
    ipLst = [] # this is our IP list for the quantity figures.

    try: # check for a valid field for our search.
        # search for our field and return the index
        index = findFields(fields, search)
        # build list for our result
        result = [rows for rows in lst
                    if (rows[index].lower() == fcat.lower()) or (re.search(fcat.lower(), rows[index].lower()))]
        result.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk
        # gather up the ip addresses for our count
        ipLst = rowInRows(result, 4)
        # raise error if nothing is returnable.
        if len(result) == 0:
            raise ValueError
    # error handling for invalid searches.
    except BaseException as err:
        print(f'\n\n[-] Invalid Search, the options you have chosen are invalid.  {err}')

    return result, ipLst

def printIP(lst)-> None:
    "Print a file of IP addresses to be used with others"
    uniqueList = []
    try:
        # open our file for printing.
        printFile = open('ip-address-output.txt', 'w')
        # add unique ip addresses to a new list
        uniqueList = rowInRows(lst, 4)
        # sort the new list
        uniqueList.sort()
        # print IP addresses into a file.
        for item in uniqueList:
            print('{:<15s} '.format(item), file= printFile)
        # close printfile
        printFile.close()
        print('IP addresses printed...')

    except IOError as err:
        print(f'File Error: {err}')

def printList(fields:list, lst:list, ipLst) -> None:
    "Handle the printing of lists by using column format printing"
    try:
        # Turn on printing if necessary
        if args.aPrint == True: turnOnPrint('sink-output.txt')
        # printing in columns
        for x, rows in enumerate(lst):
            if args.force == False:
                if (rows[3].lower() == 'critical') or (rows[3].lower() == 'high') or (rows[3].lower() == 'medium'):
                    print('[{:<1}] {:<35s} {:>7s} {:<10} {:<10} {:<15} {:<20}'.format(x+1, rows[4], rows[6], rows[5], rows[3], rows[1], rows[7]))
            else:
                print('[{:<1}] {:<35s} {:>7s} {:<10} {:<10} {:<15} {:<20}'.format(x+1, rows[4], rows[6], rows[5], rows[3], rows[1], rows[7]))
        for i in range(1,160): print('-', end='') # print line
        print('\n[{:<1}] {:<35s} {:>7s} {:<10} {:<10} {:<15} {:<20}'.format(x+1, fields[4], fields[6], fields[5], fields[3], fields[1], fields[7]))
        print("\nTotal Entries: ", len(lst)) # print record count
        print("Total IP Addresses in the list: ", len(ipLst))
        # make a printout of the core main calcs so you can see if critical/highs exist and should be examined.
        crit, high, med, low, non = calcRisk(lst, 'all')
        totNone = ((non / len(lst)) * 100)
        print(f'Risk Criteria: [Criticals: {crit}, Highs: {high}, Mediums, {med}, Lows: {low}, None: {non}, None Percent: {totNone:.2f}%]\n')
        print("Searchable Fields: ", fields, end= '\n\n')
        # Turn off printing
        if args.aPrint == True: turnOffPrint() # turn off printing
    except BaseException as err:
        print(f'Error found: {err}')

def pQuery(lst:list, num:int) -> None:
    #declare
    num = num - 1 # reduce num by one for the correct query.
    for x, rows in enumerate(lst): # enhancement to find the specfic record.
        if x == num:
            # print the last record of the name info,
            print('\n\n-------------------------------------------------------------------')
            print(f'[+] Name: {rows[7]}')
            print(f'[+] Ports        : ', rows[6])
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
            print(f'[+] IP Addresses :', rows[4])
            print('\n')

def attackFiles(lst:list) -> None:
    "Gather Eyewitness data"
    chkLst =[]
    # create our files, directories, and data elements.
    with open("eyewitness.txt", 'w') as fp:
    # open files so we can write attack files.
        for rows in lst:  # write all at once.
            if re.search("HTTP Server", rows[7]):
                eyewitness = "http://" + rows[4] + ":" + rows[6] + "\n"
                fp.write(eyewitness)
    fp.close()
    # create our snmp file for scanning.
    with open("snmp-attack.sh", 'w') as sp:
        for rows in lst:
            if re.search("SNMP Protocol Version Detection", rows[7]):
                if rows[4] not in chkLst:
                    snmpfile = 'braa public@' + rows[4] + ":.1.3.6.*\n"
                    sp.write(snmpfile)
                    chkLst.append(rows[4])
    sp.close

    print("files created...\n\n")
    print('Run each .sh file as a job task in Linux')
    print('Run eyewitness using [ eyewitness -f eyewitness.txt ]')
    print('Run snmp using [sh snmp-attack.sh]')

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

def riskGraph(crit:int,high:int,med:int,low:int) -> None:
    "Create a graph using the risk points."
    # I only want to see the graphing message if we choose to graph. No reason to run everytime.
    import matplotlib.pyplot as plt  # Turn on if were graphing only.  Don't turn on globally
    # count the values for each item.
    # gather keys and values
    keys = ['Critical:' + str(crit), 'High:' + str(high), 'Medium:' + str(med), 'Low:' + str(low)]
    values = [crit, high, med, low]
    answer = "Total Risks Found: " + str(crit + high + med + low)
    # setup color values
    c = ['#cc0000', '#ff8300', '#ffcf00', '#0000d4']
    # plot graph
    plt.bar(keys, values, align='center', color=c) # build chart
    plt.xticks(range(len(values)), keys)
    plt.xlabel(answer)
    plt.title("Vulnerabilities by Risk") # make pretty
    plt.show()

def get_pages(url) -> str:
    "Grab webpages or robots, etc."
    # grab the web pages, and text.
    try:
        webpage = requests.get(url)
        webtext = webpage.text
    except BaseException as err:
        print(f'\n\n[-] Error - {err}')

    return webtext

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

def turnOnPrint(fil:str) -> None:
    "Turn on Console Prints"
    # if were printing then set stdout to a file.
    original_stdout = sys.stdout  # save original stdout
    sys.stdout = open(fil, 'w') # write file

def turnOffPrint()-> None:
    "Turn off stdout back to original for Console Print off"
    # set stdout back
    sys.stdout = original_stdout

def merge(lst:list, fil:str)-> None:
    'Merge two different csv files together.'
    # go get our data to merge.
    fields, lst2 = openFile(fil) # go get the second file and return a list 
    print(f'Merging: {args.filename} and {fil} into a new file called new-merged-csv.csv')
    lst.extend(lst2)
    ## Save the merged file into a new file so we don't destroy original.
    with open('new-merged-csv.csv', 'w', newline='') as f: #
        write = csv.writer(f) # 
        write.writerow(fields) #
        write.writerows(lst)
    print('Finished writing CSV file: new-merged-csv.csv.  Old file preserved.\n\n')

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
    plt.plot()
    plt.xticks(rotation = 45) 
    plt.show()

def topTenIP(fields:list, lst:list, ipLst:list, amt:int) -> list:
    "Get the top 10 IP addresses from the lst, and then generate a list for those systems with total risk"
    # declare
    calcLst = []
    endLst = []
    sumRisk = 0
    # now calculate up all the risks for each host to get a top X
    for ip in tqdm(ipLst, desc='Calculating Leaders'): # run our progressbar so we can see console movement.
        for rows in lst:
            if ip in rows:
                if rows[2] != "":
                    sumRisk += float(rows[2])
        calcLst.append([ip, sumRisk])
        sumRisk = 0
    # sort all by risk value and keep top X in a list
    calcLst.sort(key= lambda x : x[1], reverse=True)    # return a sorted list by Risk Value
    del(calcLst[amt:]) # got my top X.
    # now get those rows that have all the detail for those IP's.
    endLst = [rows for ip in calcLst for rows in lst if rows[4] == ip[0]]
    endLst.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk   
    # print our new summary
    print(f'\n\nTop systems most risky are in order: ')
    for ip in calcLst:
        print('IP: {:<16} : CVE Risk Value: {:.2f}'.format(ip[0], ip[1]))

    # if we are building a graph, find it, and go do it.
    if args.sBar == True:
        print("Mapping the Chart...")
        stakBar(endLst)
    if args.cGraphics == True:
        print('Creating graphics...')
        a, b, c, d, e = calcRisk(endLst, 'all') # I won't always use e = None
        riskGraph(a,b,c,d)

def searchExploit(lst:list) -> None:
    "Search for exploits using Kali version of SearchSploit"
    # I want the cloning message displayed unless we need it.
    import cve_searchsploit as cs # load if needed
    executeLst = []
    dedup = []
    # first clone exploitdb in case its not available
    cs.update_db()
    # open our file and run through the list printing results.
    exploitFile = open('exploit.txt', 'w')
    findingsFile = open('findings.txt', 'w')
    for rows in tqdm(lst):  # progress bar as CVE to Exploits are found
        # find each cve as necessary
        if cs.edbid_from_cve(rows[1]) != []:
            if rows != dedup:
                for each in cs.edbid_from_cve(rows[1]):
                    print('IP:{:<15s}:{:<5s}/{:<4}: {:<14} : Exploit: {:<7}'.format(rows[4],rows[6], rows[5],rows[1], each), file = exploitFile)
                    if each not in executeLst:
                        subprocess.run(["searchsploit", str(each)], stdout=findingsFile)
                        executeLst.append(each)
                dedup.append(rows)
    if executeLst == []: print('No exploits found...')
    # Close me.
    exploitFile.close()
    findingsFile.close()

def nameSummary(fields:list, lst:list, search:str) -> None:
    "Build and print a list of all vulnerabilities so a quick review can be done."
    newLst = []
    index = findFields(fields, search)
    if args.aPrint == True: turnOnPrint('name-summary.txt')
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
    if args.aPrint == True: turnOffPrint()

def blood(fields:list, lst:list, fcat:str) -> None:
    "A module to review the lows for disabled users"
    mainSP = []
    # print data to a file if desired.
    if args.aPrint == True: turnOnPrint('adinfo.txt')
    # grab a list of systems that have the synopsis field for users
    newLst, ipLst = findResults(fields, lst, fcat, 'name',) 
    for rows in newLst:
        mainSP = rows[12].split('\n')
        for row in mainSP:
            if re.search('^  - ', row) or re.search('^- ', row):
                print('{:<60} \t{:<60}'.format(row, rows[4]))
    
    print("\n\n[Sample Search Strings: . user smb shares group local domain]\n\n")
    if args.aPrint == True: turnOffPrint()

# main function
def main():
    #
    #################################################
    # grab the file, and start gathering information
    fields, rows = openFile(args.filename) # Grab the data from the csv, and return fields + rows in a list
    lst, ipLst = findResults(fields, rows, args.search, args.field)  # make into a future switch

    # Do things based upon arg switches
    # create a top X report
    if args.topTen != 0:
        print('\n\nGenerating Top {:<1} List out of {:<1} findings, and {:<1} IP addresses.'.format(args.topTen, len(lst), len(ipLst)))
        topTenIP(fields, lst, ipLst, args.topTen)
        if (args.sBar != True) or (args.sBar == True):
            sys.exit()
    # create a summary and print it
    if args.summary != 0:
        nameSummary(fields, lst, args.summary)
        sys.exit()
    # create a bar graph of the results
    if args.cGraphics == True:
        print('Creating graphics...')
        a, b, c, d, e = calcRisk(lst, 'all') # I won't always use e = None
        riskGraph(a,b,c,d)
        sys.exit()
    # merge two files together
    if args.cMerge != None:
        print('Merging documents')
        merge(lst, args.cMerge)
        sys.exit()
    # create attack files for nikto, nmap and eyewitness
    if args.cAttack == True:
        print('Generating files.')
        attackFiles(lst)
        sys.exit()
    # find exploits through searchsploit
    if args.eXploit == True:
        print('Searching for exploits, check exploit.txt for findings')
        searchExploit(lst)
        sys.exit()
    # web scraping robots and other text files.
    if (args.webScrap == True) and (args.download != ""):
        print('running. file download')
        requestPage(lst, args.download)
    # printing section
    if (args.query !=0):
        pQuery(lst, args.query)
        sys.exit()
    if args.iPrint == True:
        print('\nPrinting your IP data to a file.')
        printIP(lst)
        sys.exit()
    # stacked bar sections
    if (args.sBar == True) and (args.topTen == False):
        print('\n\nYou need to perform a TOP TEN type search [-t 10] to get a stacked barchart.')
        sys.exit()
    if (args.sBar == True) and (args.topTen >= 15):
        print('\n\nYour Top 10 search cannot be greater than 15 for a stacked bar chart.')
        sys.exit()
    if args.bloodhound !=None :
        blood(fields, lst, args.bloodhound)
        sys.exit()
    if args.shodan !=False:
        sdan(lst)
        sys.exit()
    if args.address !=False:
        print('\n Generating Subnet List')
        subnetFinder(lst)
        sys.exit()
    if args.censys !=False:
        print('\n Censys Query Started')
        cen(lst) # run censys scan
        sys.exit()

    printList(fields, lst, ipLst) # print fields, and findings.
# dunder start
if __name__ == "__main__":
    main()