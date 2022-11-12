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

# run nmap
# merge multiple files into one file and print to output file .csv

# libraries
import os                           # read directory for files
import csv                          # read csv files
import re                           # search expressions
import nmap                         # run nmap for results ***
import subprocess                   # create subprocesses for scanning ***
import argparse                     # commandline argument parser ***
from collections import Counter     # counter described in week 11

#Argument Parser
parser = argparse.ArgumentParser(description='Options')
parser.add_argument("file", type=str, help='CSV filename from Nessus Pro')
parser.add_argument("field", type=str, help='field to search for the searchterm = Risk')
parser.add_argument("search", type=str, help='search term to use = Critical')
parser.add_argument('-c', '--cAttack', action='store_true', help='Automatically additional attack files and store in all output formats.')
parser.add_argument('-g', '--cGraphics', action='store_true', help='Automatically run a Nikto Attack.')
#args = parser.parse_args()

# for debugging purposes I will interchange these variables into Args and uncomment
# the line above.  Once the argument parser was active I needed a way to debug inline
# without modifying all the code to support/unsupport Args.  So this is what I did 
# to accomplish this task.  When debugging I static these entries.  When done I put 
# args.file, args.field, args.search in their place.
file = 'test.csv'
field = 'Host'
search = '10.70.1.128'
cGraphics = False
cAttack = False

# variables
flds = [] # header fields for the csv file
rows = [] # rows of data for the csv file

# open files function
def openFile(filename:str) -> list:
    "Open a nessus.csv file for fields, and rows."
    with open(filename, 'r') as csvfile:
        try:
            # open the file and grab header from csv
            csvreader = csv.reader(csvfile)
            fields = next(csvreader)
            rows = [row for row in csvreader] # List Comprehension Experiment
            
        except BaseException as err:
            print(f"Unexpected {err = }, {type(err) = }") # print my errors
    return fields, rows

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
                    if (row[rname].lower() == fcat.lower()) or (re.search(fcat, row[rname].lower()))]
        readout.sort(key= lambda x : x[3], reverse=True)    # return a sorted list by Risk

    except BaseException as err:
        print(f'\n\n[-] Invalid Search, the options you have chosen are invalid')

    return readout

def printList(fields:list, lst:list) -> None:
    "Handle the printing of lists by using column format printing"
    for row in lst:
        print('[+] {:<15s} {:<7s} {:<10} {:<10} {:<15} {:<20}'.format(row[4], row[6], row[5], row[3], row[1], row[7]))
    print('---------------------------------------------------------------------------------------------------------')
    print('[=] {:<15s} {:<7s} {:<10} {:<10} {:<15} {:<20}'.format(fields[4], fields[6], fields[5], fields[3], fields[1], fields[7]))
    print("\nFindings: ", len(lst)) # print record count

def webScannerMap(rows:list):
    nm = nmap.PortScanner()
    for row in rows:
        nm.command_line(nmap -row[4])

def attackFiles(lst:list) -> subprocess:
    "Gather Eyewitness data / nikto data and create attack files"
    with open("eyewitness.txt", 'w') as fp:
        with open("nikto.sh", 'w') as np:
            with open("http-nmap.sh", 'w') as nm:
                for row in lst:
                    if re.search("HTTP", row[7]):
                        eyewitness = "http://" + row[4] + ":" + row[6] + "\n"
                        niktoitem = "nikto -h " + row[4] + ":" + row[6] + " -o " + row[4] + "-" + row[6] + ".txt" + "\n"
                        nmapitem = "" + row[4] + "\n"
                        fp.write(eyewitness) 
                        np.write(niktoitem)
                        nm.write(nmapitem)
    print("files created...")

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
    return False


def criticalityGraph(rows:list) -> bool:
    """ Generate a graph based upon vulnerability output """
    # I only want to see the graphing message if we choose to graph.
    import matplotlib.pyplot as plt  # Turn on if were graphing only.  Don't turn on globally
    # create counters
    ccounter = 0
    hcounter = 0
    mcounter = 0
    lcounter = 0
    c = ['red', 'orange', 'yellow', 'blue']

    for row in rows:
        test = Counter(row[3])

    for row in rows:
        if row[3] == 'Critical':
            ccounter += 1
        elif row[3] == 'High':
            hcounter += 1
        elif row[3] == 'Medium':
            mcounter += 1
        elif row[3] == 'Low':
            lcounter += 1
    
    keys = ['Critical', 'High', 'Medium', 'Low']
    values = [ccounter, hcounter, mcounter, lcounter ] 

    plt.bar(keys, values, align='center', color=c) # build chart
    plt.xlabel('Vulnerabilities') # make pretty
    plt.title('Vulnerabilities Discovered') # make pretty
    plt.show()

# main function
def main():

    
    # grab our objects to use
    fields, rows = openFile(file) # Grab the data from the csv, and return fields + rows in a list
    # go get what we are looking for...
    lst = findResults(fields, rows, search, field)  # make into a future switch  -C for Critical -H for High
    printList(fields, lst) # print fields, and findings.
    print("\nSearchable Fields: ")
    print(fields, end= ' \n\n\n')
    
    # Do things based upon arg switches
    if cGraphics == True:
        criticalityGraph(lst)
    elif cAttack == True:
        attackFiles(lst)

if __name__ == "__main__":
    main()
