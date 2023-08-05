'''
DOCUMENTATION:

This is a stand-alone script that can be run by itself after doing the following steps:
NOTE: This script will send all files that are created and closed DURING its lifetime in the watched directory.

NOTE: watchdog package must be installed on machine already with 'pip install watchdog'
NOTE: This script was tested and can be run with Python 3.8
NOTE: This script will be added to the client machine
    - To run the script as a daemon (i.e. background service) make sure systemd works and the watchdog package is installed 
    
    - Add the service name in system folder: sudo nano /etc/systemd/system/client_logSender.service
        - add the following inside:
            [Unit]
            Description=Python script service for sending new snort logs to scanner machine
            After=multi-user.target
            
            [Service]
            Type=simple
            Restart=always
            Environment=PYTHONUNBUFFERED=1
            ExecStart=/usr/bin/python3.8 /home/vagrant/client_logSender.py
            
            [Install]
            WantedBy=multi-user.target 
        
        - Then reload the daemon:
            - sudo systemctl daemon-reload
        
        - Then enable the service (it will not get disabled if server restarts):
            - sudo systemctl enable client_logSender.service
        
        - Start the service:
            - sudo systemctl start client_logSender.service
        
        - You can end, restart, or check status of the service with:
            - sudo systemctl {stop | restart | status} client_logSender
'''

from pathlib import Path
import ftplib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# PUBLIC VARIABLES
snort_log_fldr_path = '/var/log/snort'
scanner_IP = 'the_ip'
scanner_USERNAME = 'user'
scanner_PASSWORD = 'passwd'
scanner_FTP_RECEIVED_LOGS_FLDR = "/the/path/to/the/logs"

class NewLogCreationScan(FileSystemEventHandler):
    def __init__(self):
        self.sent_log_files = dict() #{filePath : sent? (True, False)}

    def on_created(self, event): 
        # when file is created
        filePath = event.src_path
        print (f"ALERT - Detected created file: {filePath}") 
        
        if not self.addIfNewFile(filePath):
            print (f"WARNING - the file: {filePath} has already been seen") 

    def on_closed(self, event):
        # when file is written and closed
        filePath = event.src_path
        self.sendFileOverFTP(scanner_IP, scanner_USERNAME, scanner_PASSWORD, filePath)

    def addIfNewFile(self, filePath:str):
        # returns False if file is already seen or True after adding the file to the sent_log_files dict
        if filePath in self.sent_log_files.keys():
            return False
        else:
            print(f"ALERT - Adding new file to eventually send: {filePath}")
            self.sent_log_files[filePath] = False
            return True

    def sendFileOverFTP(self, ip:str, username_value:str, password_value:str, filePath:str):
        if self.sent_log_files.get(filePath) == False: # check if the file is already sent
            
                session = ftplib.FTP(ip,username_value,password_value)
                        
                try:
                    session.cwd(scanner_FTP_RECEIVED_LOGS_FLDR)
                except Exception as e:
                    print(f"WARNING - The expected remote directory {scanner_FTP_RECEIVED_LOGS_FLDR} did not exist. Creating it now")
                    session.mkd(scanner_FTP_RECEIVED_LOGS_FLDR)
                    session.cwd(scanner_FTP_RECEIVED_LOGS_FLDR)

                file_p = open(filePath,'rb')

                fileName = Path(filePath).name
                print(f"ALERT - Sending to scanner machine the file: {fileName}")

                session.storbinary('STOR ' + fileName, file_p)
                file_p.close()
                session.quit()
                self.sent_log_files[filePath] = True # mark file as sent
        else:
            print(f"WARNING - file on path {filePath} is not being sent since it already has")

    
    

observer = Observer()
event_handler = NewLogCreationScan() # create event handler
# set observer to use created handler in directory
observer.schedule(event_handler, path=snort_log_fldr_path)
observer.start()

observer.join()