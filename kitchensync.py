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

def printData(rows:list, fields:list, category:str) -> None:
    "Receive a list of rows, and a field and print the results."
    readout = [] # this is the finding from the list.
    print(f"fields: ",fields[7],end=" ")
    for row in rows:
        if category == "Critical":
            if row[2] >= "7":
                readout.append(row)
        elif category == "High":
            if (row[2] >=5) or (row[2] <= 7):
                readout.append(row)

# main function
def main():
    # grab our objects to use
    fields = openFile(fileName, "fields")
    rows = openFile(fileName, "rows")



    # test printing 
    print('\nFirst 5 rows are:\n')
    for row in rows[:5]:
        # parsing each column of a row
        for col in row:
            print("%10s"%col,end=" "),
    print('\n')

if __name__ == "__main__":
    main()
