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
# Run as subprocess
# run nikto
# merge multiple files into one file and print to output file .csv
# command line arguments

# libraries
import csv                          # read csv files
import re                           # search expressions
from columnar import columnar       # print strings in columns

# Argv variables
fileName = "C:\\Users\\jerry\\Dropbox\\Desktop Items\\Harvard\\CSCI-E7 - Python\\Project\\Project\\test.csv"  # future argv object
desired = [] # future critical/high/etc.

# variables
flds = [] # header fields for the csv file
rows = [] # rows of data for the csv file

# open files function
"Open a nessus.csv file for fields, and rows."
def openFile(filename:str) -> list:
    with open(filename, 'r') as csvfile:
        try:
            # open the file and grab header from csv
            csvreader = csv.reader(csvfile)
            fields = next(csvreader)
            # gather the rows and put them into a list
            for row in csvreader:
                rows.append(row)
        except BaseException as err:
            print(f"Unexpected {err = }, {type(err) = }") # print my errors

    return fields, rows

def findResults(fields:list, rows:list, fcat:str, search:str) -> list:
    "universal field search feature, tell me the field, and the string, and I will find it"
    readout = [] # this is the results from the search.

    for field in fields:  # find desired field
        if search == field:
            rname = fields.index(field)
            break     

    for row in rows: ## find results from field
        if (row[rname] == fcat) or (re.search(fcat, row[rname])):  #Grab what we asked for
            readout.append(row)    
    return readout

def printList(lst:list) -> None:
    "Handle the printing of lists"
    
    for row in lst:
        print(f'{row[4]}\t{row[6]}\t{row[3]} {row[1]}     {row[7]}\t')
    print("\nFindings: ", len(lst)) # print record count


# main function
def main():
    # grab our objects to use
    fields, rows = openFile(fileName)

    lst = findResults(fields, rows, "10.2.1.126", "Host")  # make into a future switch  -C for Critical -H for High
    printList(lst)
    print("\nSortable Fields: ")
    print(fields, end= ' \n\n\n')



if __name__ == "__main__":
    main()
