# kitchensync.py
# Author: Jerry Craft
# October 21, 2022
#
# KitchenSink.py -- Everything and the kitchen sink for Nessus files
# This program is an all around clean up tool I am designing to help me with my 
# penetration testing problems.  This tool is surrounded around the idea that Tenable Nessus Pro
# while doing a good job at vunlerability scanning, fails to provide me with reasonable reporting
# mechanisms.  So this tool will make up for the several shortcomings by slicing, dicing, and manipulating
# data from Tenable Nessus CSV files.

# BEST IF RUN ON KALI LINUX.  SEARCHSPLOIT DATABASES NEED TO BE INSTALLED ON THE COMPUTER RUNNING THIS FILE.

# libraries                             # anything with a *** are libraries that were outside of class.
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
        epilog='Compiled for Python 3.9. The libraries needed are: sys, csv, re, argparse, requests, tqdm, matplotlib, searchsploit ' +
        '[https://github.com/andreafioraldi/cve_searchsploit]')

parser.add_argument("filename", type=str, help='The [filename] of CSV to read and display.  These are the results you want.')
parser.add_argument('-bar', '--sBar', action='store_true', default=False, help='Generate a stacked barchart on the results of a TOPTEN type search only')
parser.add_argument('-c', '--cAttack', action='store_true', default=False, help='Automatically create attack files and store in all output formats.')
parser.add_argument('-download', '--download', type=str, default='robots.txt', help='Download a file, and list the filename to name the file after its been downloaded [ex. -d robots.txt].  Text file only.')
parser.add_argument('-f', '--field', type=str, default='host', help='The field to search for in the data set [-s Risk]')
parser.add_argument('-graph', '--cGraphics', action='store_true', default=False, help='Create a graph of the vulnerability risks for any search.  Run a search and use [-g] at the end.')
parser.add_argument('-ip', '--iPrint', action ='store_true', default=False, help='Print a file of the IP addresses of a search.  Run a search and put [-p] at the end')
parser.add_argument('-merge', '--cMerge', type=str, help='Merge two Nessus CSV files together.  [kitchensink.py test.csv -m second.csv] the merged file will be new-merged-csv.csv')
parser.add_argument('-print', '--aPrint', action='store_true', default=False, help='Print search output to a file.  Run grep/awk on this file to pull data as necessary')
parser.add_argument('-q', '--query', action='store_true', default=False, help='Expand the information on a particular finding. SEARCH field cannot be a wildcard ![-s .]!. It must be a specific search.')
parser.add_argument('-s', '--search', type=str, default='.', help='search term to use [ -s Critical].  [ a period . is a wildcard for all]')
parser.add_argument('-sum', '--summary', action='store_true', default=False, help='List all types of vulnability names discovered.  This is a simple list to aid in searching data.')
parser.add_argument('-top', '--topTen', type=int, default=False, help='Generate a top 10 list of systems, and risks.  using [ -b ] together will generate a stacked bar chart.')
parser.add_argument('-w', '--webScrap', action='store_true', default=False, help='WebScrape to a file. Example [robots.txt]')
parser.add_argument('-x', '--eXploit', action='store_true', default=False, help='Run SearchSploit to find an exploit based upon a list of CVEs searched.')
args = parser.parse_args()

#global variables
original_stdout = sys.stdout # grab a copy of standard out now before we do any console prints.

############################################################
# open files function
def openFile(filename:str) -> list:
    "Open a nessus.csv file for fields, and rows."
    try:
        with open(filename, 'r') as csvfile:       
            # open the file and grab header from csv
            csvreader = csv.reader(csvfile)
            fields = next(csvreader)
            rows = [row for row in csvreader] # [List Comprehension Experiment]
    
    except csv.Error as err:
        print(f'\nError in reading the CSV file.  Check your file.\n\n')
    except IOError as err:
        print(f'\nFilename of the Nessus Pro CSV mandatory, file not found.\n\n')

    return fields, rows
############################################################

def findResults(fields:list, lst:list, fcat:str, search:str) -> list:
    "universal field search feature, tell me the field, and the string, and I will find it"
    readout = [] # this is the results from the search.
    ipLst = []

    try:
        for field in fields:  # find desired field
            if search.lower() == field.lower():
                rname = fields.index(field)
                break
            
        # build list for our readout [List Comprehension decision for experiment]
        readout = [rows for rows in lst
                    if (rows[rname].lower() == fcat.lower()) or (re.search(fcat.lower(), rows[rname].lower()))]

               # sort key lambda JDP and https://blogboard.io/blog/knowledge/python-sorted-lambda/
        readout.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk

        # gather up the ip addresses for our count
        for rows in readout:
            if rows[4] not in ipLst:
                ipLst.append(rows[4])

        # raise error if nothing is returnable.
        if len(readout) == 0:
            raise ValueError

    except BaseException as err:
        print(f'\n\n[-] Invalid Search, the options you have chosen are invalid.  {err}')

    return readout, ipLst
#############################################################
def printIP(lst)-> None:
    "Print a file of IP addresses to be used with others"
    # print only IP addresses
    uniqueList = []
    printfile = open('ip-address-output.txt', 'w') 
    # add unique ip addresses to a new list
    for rows in lst:
            if rows[4] not in uniqueList:
                uniqueList.append(rows[4])
    # sort the new list
    uniqueList.sort()
    # print IP addresses into a file.
    for item in uniqueList:
        print('{:<15s} '.format(item), file= printfile)
    printfile.close()
    print('IP addresses printed...')
#############################################################

def printList(fields:list, lst:list, ipLst) -> None:
    "Handle the printing of lists by using column format printing" 
    # Turn on printing if necessary
    if args.aPrint == True:
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
    if args.aPrint == True:
        turnOffPrint() # turn off printing
        print('Printing done...\n\n')
    
################################################################

def pQuery(lst:list) -> None:
    #declare
    ipLst = []
    portLst = []
    for rows in lst:
        # gather IP addresses and put into a string
        if rows[4] not in ipLst:
            ipLst.append(rows[4])
        if rows[6] not in portLst:
            portLst.append(rows[6])
    # print 1 record of what the name info, and add all the IP's affected by that issue.
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

def attackFiles(lst:list):
    "Gather Eyewitness data / nikto data and create attack files"
    with open("eyewitness.txt", 'w') as fp:
        with open("nikto.sh", 'w') as np:
            with open("http-nmap.sh", 'w') as nm:       # open files so we can write attack files.
                for rows in lst:                         # write all at once.
                    if re.search("HTTP", rows[7]):
                        eyewitness = "http://" + rows[4] + ":" + rows[6] + "\n"
                        niktoitem = "nikto -h " + rows[4] + ":" + rows[6] + " -o " + rows[4] + "-" + rows[6] + ".txt" + "\n"
                        nmapitem = "nmap" + ' -sV' + ' -sC ' + rows[4] + ' --script=http*' + ' -oA ' + rows[4] + "-nmap" + "\n"
                        fp.write(eyewitness) 
                        np.write(niktoitem)
                        nm.write(nmapitem)
    print("files created...\n\n")

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
    # found this method: https://www.programiz.com/python-programming/methods/list/count
    if item != 'all':
        for rows in lst:
            if (rows[4] == item):
                newLst.append(rows)
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
            
    # return multiple: https://note.nkmk.me/en/python-function-return-multiple-values/
    return ccounter, hcounter, mcounter, lcounter, ncounter
#############################################################

def riskGraph(crit:int,high:int,med:int,low:int) -> bool:
    "Create a graph using the risk points."
    # I only want to see the graphing message if we choose to graph.
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
    webpage = requests.get(url)
    webtext = webpage.text
    return webtext
#######################################################

def requestPage(lst:list, req:str):
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

def turnOnPrint(fil:str):
    "Turn on Console Prints"
    # if were printing then set stdout to a file. 
    # (https://www.delftstack.com/howto/python/python-output-to-file/)
    
    original_stdout = sys.stdout  # save original stdout
    sys.stdout = open(fil, 'w') # write file
#########################################################

def turnOffPrint():
    "Turn off stdout back to original for Console Print off"
    # set stdout back
    sys.stdout = original_stdout
##########################################################

def merge(lst:list, fil:str)-> list:
    'Merge two different csv files together.'
    fields, lst2 = openFile(fil) # go get the second file and return a list
    lst.extend(lst2) # https://www.w3schools.com/python/gloss_python_join_lists.asp
    print(f'Merging: {args.filename} and {fil} into a new file called new-merged-csv.csv')
    ## Save the merged file into a new file so we don't destroy original.
    with open('new-merged-csv.csv', 'w', newline='') as f: # 
        write = csv.writer(f) # https://stackoverflow.com/questions/3348460/csv-file-written-with-python-has-blank-lines-between-each-row
        write.writerow(fields) #https://www.geeksforgeeks.org/python-save-list-to-csv/
        write.writerows(lst)
    print('Finished writing CSV file: new-merged-csv.csv.  Old file preserved.\n\n')
    
##############################################################

def stakBar(lst:list):
    "Generate a stacked bar chart to help understand results"
    import matplotlib.pyplot as plt
    crit = 0
    high = 0
    med = 0
    low = 0
    nan = 0
    newLst = []

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

def topTenIP(lst:list, amt) -> list:
    "Get the top 10 IP addresses from the lst, and then generate a list for those systems with total risk"
    # declare
    topIP = []
    finalLst = []
    calcLst = []
    sumRisk = 0
    
    # get a list of host addresses to begin
    for rows in lst:
        if rows[4] not in topIP:
            topIP.append(rows[4])
    # now get a list of all vulnerabilities for these hosts
    fields, rows = openFile(args.filename)
    for ip in tqdm(topIP, desc="Pull List:"): # run our progressbar so we can see console movement.
        for row in rows: #https://medium.com/@harshit4084/track-your-loop-using-tqdm-7-ways-progress-bars-in-python-make-things-easier-fcbbb9233f24
            if ip == row[4]:
                finalLst.append(row)
    # now calculate up all the risks for each host to get a top 10
    for ip in tqdm(topIP, desc='Calc List:'): # run our progressbar so we can see console movement.
        for rows in finalLst:
            if ip in rows:
                if rows[2] != "":
                    sumRisk += float(rows[2])
        calcLst.append([ip, sumRisk])
        sumRisk = 0
    # sort all by risk value and keep top 10 in a list
    calcLst.sort(key= lambda x : x[1], reverse=True)    # return a sorted list by Risk Value
    del(calcLst[amt:]) # got my top 10.
    # now get those rows that have all the detail for those IP's.
    lst.clear() # reuse lst.
    for ip in calcLst:
        for rows in finalLst:
            if rows[4] == ip[0]:
                lst.append(rows)
    lst.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk
    printList(fields, lst, calcLst)
    print(f'Top systems most risky are in order: ')
    for ip in calcLst:
        print('IP: {:<16} : CVE Risk Value: {:.2f}'.format(ip[0], ip[1]))
    
    if args.sBar == True:
        stakBar(lst)
    ####################################################

def searchExploit(lst:list) -> None:
    "Search for exploits using Kali version of SearchSploit"
    import cve_searchsploit as cs # load if needed
    resultLst = []
    # first clone exploitdb in case its not available
    #cs.update_db()
    exploitFile = open('exploit.txt', 'w')
    for rows in tqdm(lst):  # progress bar as CVE to Exploits are found
        # find each cve as necessary
        if cs.edbid_from_cve(rows[1]) != []:
            if rows[1] not in resultLst: # if CVE has already been seen, move on.
                resultLst.append(rows[1]) # add to list and print
                print(f'CVE: {rows[1]} and Exploit: ', cs.edbid_from_cve(rows[1]), file = exploitFile)
    exploitFile.close()

#####################################################
def nameSummary(lst:list) -> list:
    "Build and print a list of all vulnerabilities so a quick review can be done."
    newLst = []
    # grab list and start sorting out names into a new list
    for rows in lst:
        if rows[7] not in newLst:
            newLst.append(rows[7])
    newLst.sort(key= lambda x : x)
    for row in newLst:
        print('[+]', row)
    print('--------------------------------------------------------')
    print('[=] Field to search = Name')
    print("\n\n")

#####################################################
# main function
def main():
    #
    #################################################
    # grab the file, and start gathering information
    fields, rows = openFile(args.filename) # Grab the data from the csv, and return fields + rows in a list
    # go get what we are looking for...
    lst, ipLst = findResults(fields, rows, args.search, args.field)  # make into a future switch  -C for Critical -H for High
    # abort if something goes unexpected and returns nothing.
    if len(lst) == 0: 
        print('\nSearch returned nothing, check your search and try again.\n') 
        sys.exit()
    ################################################
    # Do things based upon arg switches

    # create a top X report
    if args.topTen != 0:
        print('\n\nGenerating Top list')
        topTenIP(rows, args.topTen)
        sys.exit()
    # create a summary and print it
    if args.summary == True:
        nameSummary(lst)
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
    if (args.search != '.') and (args.query == True):
        pQuery(lst)
        sys.exit()
    elif(args.search == '.') and (args.query == True):
        print('\nYour query failed.  You need to narrow the search to a single name field item to inspect the details.\n\n')
        sys.exit()
    # stacked bar section 
    if args.sBar == True and args.topTen == False:
        print('You need to perform a TOP TEN type search [-t 10] to get a stacked barchart.')
        sys.exit()

    # otherwise always print this list, either to a file or to the screen.
    printList(fields, lst, ipLst) # print fields, and findings.
    ###############################################

# dunder start
if __name__ == "__main__":
    main()
