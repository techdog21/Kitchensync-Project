# kitchensync.py
# Author: Jerry Craft
# Project for CSCI E-7 Python
# October 21, 2022
#
# KitchenSink.py 
# This program is an all around clean up tool I am designing to help me with my 
# penetration testing problems.  This tool is surrounded around the idea that Tenable Nessus Pro
# while doing a good job at vunlerability scanning, fails to provide me with reasonable reporting
# mechanisms.  So this tool will make up for the several shortcomings by slicing, dicing, and manipulating
# data from Tenable Nessus CSV files.
#
# This tool will also do some basic recon, and other basic actions to improve testing habits.

# run nmap
# merge multiple files into one file and print to output file .csv

# libraries                         # anything with a *** are libraries that were outside of class.
import os                           # read directory for files
import sys                          # printing to a file
import csv                          # read csv files
import re                           # search expressions
import subprocess                   # create subprocesses for scanning ***
import argparse                     # commandline argument parser ***
import requests                     # grab robots.txt and other text, html files.

# Argument Parser
# This sets up our arguments and help/options for the user
# discovered argparse: https://towardsdatascience.com/a-simple-guide-to-command-line-arguments-with-argparse-6824c30ab1c3
parser = argparse.ArgumentParser(description='Options')
parser.add_argument("filename", type=str, help='filename of CSV to read')
parser.add_argument('-a', '--action', action='store_true', default=False, help='Run a type of attack type [nmap / nikto / eyewitness / all], all for all attacks')
parser.add_argument('-c', '--cAttack', action='store_true', default=False, help='Automatically additional attack files and store in all output formats.')
parser.add_argument('-d', '--download', type=str, default='robots.txt', help='file to download ex. robots.txt.  Text file only.')
parser.add_argument('-f', '--field', type=str, default='host', help='field to search for the searchterm = Risk')
parser.add_argument('-g', '--cGraphics', action='store_true', default=False, help='Create a graph of the vulnerability risks.')
parser.add_argument('-i', '--iPrint', action ='store_true', default=False, help='Print only IP addresses to a file, must be used with -p argument too')
parser.add_argument('-p', '--aPrint', action='store_true', default=False, help='Print output to a file')
parser.add_argument('-r', '--rAttack', action='store_true', default=False, help='Run the attack after the files were created')
parser.add_argument('-s', '--search', type=str, default='.', help='search term to use = Critical.  [ a period . is a wildcard for all]')
parser.add_argument('-w', '--webScrap', action='store_true', default=False, help='Scrap to a file. Example robots.txt')
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
            
    except BaseException as err:
            print(f'Filename of the Nessus Pro CSV mandatory')

    return fields, rows
############################################################

def findResults(fields:list, rows:list, fcat:str, search:str) -> list:
    "universal field search feature, tell me the field, and the string, and I will find it"
    readout = [] # this is the results from the search.
    try:
        for field in fields:  # find desired field
            if search.lower() == field.lower():
                rname = fields.index(field)
                break

        # build list for our readout [List Comprehension decision for experiment]
        readout = [row for row in rows
                    if (row[rname].lower() == fcat.lower()) or (re.search(fcat.lower(), row[rname].lower()))]
        # sort key lambda JDP and https://blogboard.io/blog/knowledge/python-sorted-lambda/
        readout.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk

    except BaseException as err:
        print(f'\n\n[-] Invalid Search, the options you have chosen are invalid')

    return readout
#############################################################

def printList(fields:list, lst:list) -> None:
    "Handle the printing of lists by using column format printing"
    # if were printing then set stdout to a file. 
    # (https://www.delftstack.com/howto/python/python-output-to-file/)
    if (args.aPrint == True) and (args.iPrint == True):
        # print only IP addresses
        uniqueList = []
        turnOnPrint('sink-output.txt') # turn on std console print
        for row in lst:
            if row[4] not in uniqueList:
                uniqueList.append(row[4])
        for item in uniqueList:
            uniqueList.sort()
            print('{:<15s} '.format(item))

        turnOffPrint() # my own function to turn off console print.
    else:
        # print standard output, and print to file if desired
        if args.aPrint == True: 
            turnOnPrint('sink-output.txt') # turn on std console print
        # printing in columns: https://scientificallysound.org/2016/10/17/python-print3/
        for row in lst:
            print('[+] {:<15s} {:<7s} {:<10} {:<10} {:<15} {:<20}'.format(row[4], row[6], row[5], row[3], row[1], row[7]))
        print('---------------------------------------------------------------------------------------------------------')
        print('[=] {:<15s} {:<7s} {:<10} {:<10} {:<15} {:<20}'.format(fields[4], fields[6], fields[5], fields[3], fields[1], fields[7]))
        print("\nTotal Entries: ", len(lst)) # print record count

        # make a printout of the core main calcs so you can see if critical/highs exist and should be examined.
        crit, high, med, low, non = calcRisk(lst)
        print(f'Risk Criteria [Criticals: {crit}, Highs: {high}, Mediums, {med}, Lows: {low}, None: {non}]\n')
        turnOffPrint() # turn off printing
    
################################################################

def attackFiles(lst:list) -> subprocess:
    "Gather Eyewitness data / nikto data and create attack files"
    with open("eyewitness.txt", 'w') as fp:
        with open("nikto.sh", 'w') as np:
            with open("http-nmap.sh", 'w') as nm:       # open files so we can write attack files.
                for row in lst:                         # write all at once.
                    if re.search("HTTP", row[7]):
                        eyewitness = "http://" + row[4] + ":" + row[6] + "\n"
                        niktoitem = "nikto -h " + row[4] + ":" + row[6] + " -o " + row[4] + "-" + row[6] + ".txt" + "\n"
                        nmapitem = "nmap" + ' -sV' + ' -sC ' + row[4] + ' --script=http*' + ' -oA ' + row[4] + "-nmap" + "\n"
                        fp.write(eyewitness) 
                        np.write(niktoitem)
                        nm.write(nmapitem)
    print("files created...")
###################################################################

def runMe(prog:str) -> bool:
    """Take a string for the program to run, and return bool if success/fail"""
    if prog.lower() == "eyewitness" or prog.lower() == 'all':
        if os.path.exists('eyewitness.txt'):
            subprocess.call(["eyewitness", "-f", "./eyewitness.txt", "--web"])
            return True
        else: 
            return False
    if prog.lower() == 'nikto' or prog.lower() == 'all':
        if os.path.exists('nikto.sh'):
            subprocess.call(["nikto.sh"])
            return True
        else:
            return False
    if prog.lower() == 'nmap' or prog.lower() == 'all':
        if os.path.exists('nmap'):
            subprocess.run(["nmap", "-sS", "-sC", '-iL', 'http-nmap.txt', "--script=http*", "-oN", 'results' + "-nmap"])
    return False
#####################################################################

def calcRisk(rows:list) -> bool:
    """ Generate risk figures for detailed data points """    
    # create counters
    ccounter = 0
    hcounter = 0
    mcounter = 0
    lcounter = 0
    ncounter = 0
    # found this method: https://www.programiz.com/python-programming/methods/list/count
    for row in rows:
        ccounter += row[3].count('Critical')
        hcounter += row[3].count('High')
        mcounter += row[3].count('Medium')
        lcounter += row[3].count('Low')
        ncounter += row[3].count('None')
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
    keys = ['Critical', 'High', 'Medium', 'Low']
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

# main function
def main():
    #
    #################################################
    # grab the file, and start gathering information
    fields, rows = openFile(args.filename) # Grab the data from the csv, and return fields + rows in a list
    # go get what we are looking for...
    lst = findResults(fields, rows, args.search, args.field)  # make into a future switch  -C for Critical -H for High
    printList(fields, lst) # print fields, and findings.
    print("\nSearchable Fields: ", fields, end= '\n') # print seperator
    print("Search for all records:  python kitchensink.py test.csv -s . -f Solution \n\n ")
    ################################################
    # Do things based upon arg switches
    if args.cGraphics == True:
        a, b, c, d, e = calcRisk(lst) # I won't always use e = None
        riskGraph(a,b,c,d)
    if args.cAttack == True:
        attackFiles(lst)
    if args.rAttack == True:
        runMe(args.action)
    if args.webScrap == True:
        print('running. file download')
        requestPage(lst, args.download)
    ###############################################

# dunder start
if __name__ == "__main__":
    main()