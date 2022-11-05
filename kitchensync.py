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

# libraries
import csv

# Argv variables
fileName = "test.csv"  # future argv object

# variables
flds = [] # header fields for the csv file
rows = [] # rows of data for the csv file


# open files function
"Open a nessus.csv file for fields, and rows."
def openFile(filename:str, output:str) -> list:
    with open(filename, 'r') as csvfile:
        try:
            # open the file and grab header from csv
            csvreader = csv.reader(csvfile)
            fields = next(csvreader)
            # gather the rows and put them into a list
            if output == "rows":
                for row in csvreader:
                    rows.append(row)
                return rows
            elif output == "fields":
                return fields
        except BaseException as err:
            print(f"Unexpected {err = }, {type(err) = }") # print my errors

def printSpecificResults(rows:list, fields:list, category:str) -> list:
    "Receive a list of rows, and a field and print the specific results."
    readout = [] # this is the results from the search.

                    readout.append(row)
    return readout

def printList(lst:list) -> None:
    "Handle the printing of lists"
    for row in lst:
        print(f'Name: {row[7]}')

# main function
def main():
    # grab our objects to use
    fields = openFile(fileName, "fields")
    rows = openFile(fileName, "rows")
    lst = printSpecificResults(rows, fields, "Critical")  # make into a future switch  -C for Critical -H for High
    printList(lst)



if __name__ == "__main__":
    main()
