'''
DOCUMENTATION:

This is a script that requires the Makefile, and a C header and source file with potentiolly malicious OS syscalls to be present in the same folder where it is.

NOTE: This script will process all files in the watched directory (excluding alert files)

NOTE: if pip3 is not installed, install it to add the necesary modulesfor python3.6
NOTE: The scanner machine root is unable to see the watchdog & pyshark when starting the script as daemon so the USER has been specified
NOTE: watchdog package must be installed on machine already with 'sudo pip3 install watchdog'
NOTE: pyshark package must be installed on machine already with 'sudo pip3 install pyshark'

NOTE: This script was tested and can be run with Python 3.6
NOTE: This script will be added to the scanner machine
    - To run the script as a daemon (i.e. background service) make sure systemd works and the pyshark package is installed
    
    - Add the service name in system folder: sudo nano /etc/systemd/system/scanner_sysCallDetect.service
        - add the following inside:
            [Unit]
            Description=Python script service for processing new snort logs in scanner machine
            After=multi-user.target
            
            [Service]
            Type=simple
            Restart=always
            Environment=PYTHONUNBUFFERED=1
            ExecStart=/usr/bin/sudo /usr/bin/python3.6 /your/path/scanner_sysCallDetect.py
            
            [Install]
            WantedBy=multi-user.target 
        
        - Then reload the daemon:
            - sudo systemctl daemon-reload
        
        - Then enable the service (it will not get disabled if server restarts):
            - sudo systemctl enable scanner_sysCallDetect.service
        
        - Start the service:
            - sudo systemctl start canner_sysCallDetect.service
        
        - You can end, restart, or check status of the service with:
            - sudo systemctl {stop | restart | status} scanner_sysCallDetect
NOTE: you may need to set the file permissions to include execute via: sudo chmod 755 scanner_sysCallDetect.service BEFORE you enable the service
'''

import os
import hashlib
import time
import pyshark
from pathlib import Path
import subprocess
import tempfile
from multiprocessing import Queue
import uuid

scanner_FOLDER = "/home/Documents/scan_fldr"
scanner_RECEIVED_LOGS_FLDR = "/home/Documents/Received_Logs"

executed_PCAP_pkt_binaries_hashes = set()
files_processed_or_skipped = set()
files_to_process_queue = Queue()

def checkIfNewLogFile(filePath:str):
    #check if the file is a log file or an alert file (which we will skip)
    if filePath in files_processed_or_skipped:
        return False
    elif "alert" in filePath.rsplit('/', 1)[1]:
        files_processed_or_skipped.add(filePath)
        return False
    else:
        files_processed_or_skipped.add(filePath) # adding this file also to not get the alert again
        print(f"ALERT - Adding new file to eventually process: {filePath}")
        return True

def scanForNewFilesToProcess():
    for fileName in os.listdir(scanner_RECEIVED_LOGS_FLDR):
        full_filePath = scanner_RECEIVED_LOGS_FLDR+"/"+fileName
        if os.path.isfile(full_filePath) and checkIfNewLogFile(full_filePath):
            files_to_process_queue.put(full_filePath)

def processFileForBinaries(filePath:str):
    print(f"ALERT - Extracting binaries from the file: {filePath}")

    full_pcap = pyshark.FileCapture(filePath)

    bin_pkt_num = 0 # FOR DEBUGGING ONLY
    bin_pkt_executed = 0 # FOR DEBUGGING ONLY
    
    full_pcap_ls = list(full_pcap)
    print(f"ALERT - Extracting a total of {len(full_pcap_ls)} binaries from the file: {filePath}\n")

    for pkt in full_pcap_ls:
        bin_pkt_num += 1
        try:
            bin_val = pkt.tcp.payload.binary_value
            pkt_hash = hashlib.md5(pkt.tcp.payload.binary_value).hexdigest()

            if pkt_hash not in executed_PCAP_pkt_binaries_hashes: # check if the hash of the packet binary has not already been seen
                executed_PCAP_pkt_binaries_hashes.add(pkt_hash)
                executeBinary(bin_val)
                
                
                bin_pkt_executed += 1
            else:
                print (f"WARNING - Packet number {bin_pkt_num} for the file {filePath} has already been seen and executed. Skipping") 
        except: 
            pass
    print(f"ALERT - All {bin_pkt_executed} new binaries from the file {filePath} have been executed and file is processed")


def executeBinary(bin_val):
    # creates a temporary file to store the binary conetn and then executes it
    # after running all neccessary commands and subsequently after execution deletes the file
    
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as tmp:
            tmp.write(bin_val)

        print(f"ALERT - Executing temporary binary file: {path}")
        
        subprocess.run("make clean", shell=True, stdout=subprocess.DEVNULL)
        subprocess.run("make -f Makefile", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("dmesg --clear", shell=True, stdout=subprocess.DEVNULL) 
        subprocess.run("insmod hooks.ko", shell=True, stdout=subprocess.DEVNULL)
        
        cmd = f"chmod a+x {path}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)
        
        cmd = f"ls -l {path}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)     
        subprocess.run("rmmod hooks.ko", shell=True, stdout=subprocess.DEVNULL)

    except Exception as e:
        print(f"ERROR - Error during binary execution: {e}")
    finally:
        os.remove(path)


def main():
    os.chdir(scanner_FOLDER)
    os.makedirs(scanner_RECEIVED_LOGS_FLDR, exist_ok=True)  # silently checks if folder exsits otherwise creates it 
    
    # the main daemon loop function
    while True:
        
        scanForNewFilesToProcess()

        while not files_to_process_queue.empty(): # process all new files
            file_fullpath = files_to_process_queue.get()
            processFileForBinaries(file_fullpath)

        time.sleep(1)


main()