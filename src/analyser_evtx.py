#Reading evtx (Windows logs)
from Evtx.Evtx import Evtx
#Getting fields from XML
import xml.etree.ElementTree as ET
#()init ensures colors work in Windows console; Fore - text color;
from colorama import Fore, Style
from datetime import timedelta, datetime
import csv
FAILED_THRESHOLD = 5
failed_logons = {}
SUSPICIOUS_PROCESSES = {"powershell.exe":"HIGH", "cmd.exe":"MEDIUM", "rundll32.exe": "HIGH", "mshta.exe": "HIGH", "wmic.exe": "MEDIUM", "certutil.exe": "HIGH"}
#Namespace
ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
def parse(file_path):
    #4624:Indicates Successful authentication, 4625(Failed login):Helps detect brute force, 4776(NTLM authentication attempt): Used for detecting NTLM logins
    #4769(Kerberos service ticket granted):Identifies lateral movement using Kerberos
    #4674(Sensitive privilege used):Detects actions requiring admin privileges
    #4698(Scheduled task created):Could indicate malware persistence
    #4688:(Process Creation)
    #4720(User account created), 4722(User account enabled),4740(Account locked due to failed logins),4732(User added to admin group)
    SECURITY_EVENTS = { "4624","4625", "4776" ,"4768", "4769", "4688", "4674", "4698", "4720","4722","4740","4732" }
    with (Evtx(file_path) as log):
        for record in log.records():
            xml = record.xml()
            root = ET.fromstring(xml)

            event_id = root.find(".//e:EventID",ns)

            time_created = root.find(".//e:TimeCreated",ns).get("SystemTime")

            if event_id.text in SECURITY_EVENTS:
                if event_id.text == "4625":
                    process_name = root.find(".//e:Data[@Name='ProcessName']", ns)
                    process_elem = process_name.text if process_name is not None else "No process"

                    user_elem = root.find(".//e:Data[@Name='TargetUserName']", ns)
                    username = user_elem.text if user_elem is not None else "N/A"
                    failed_logons[username] = failed_logons.get(username,0) + 1
                    #Style.RESET_ALL - resets color after printing
                    print(f"[FAILED LOGON] EventID: {event_id.text} | TargetUserName: {username} | Timecreated: {time_created} | Process: {process_elem}")

                    if failed_logons[username] == FAILED_THRESHOLD:
                        print(Fore.RED + f"[ALERT] Possible BRUTE-FORCE on user {username}" + Style.RESET_ALL)

                elif event_id.text == "4624":
                    ...
                elif event_id.text == "4688":
                    proc_elem = root.find(".//Date[@Name='NewProcessName']",ns)
                    process = proc_elem.text if proc_elem is not None else "N/A"
                    print(process)
                elif event_id.text == "4768":
                    ...
                elif event_id.text == "4769":
                    ...
                elif event_id.text == "4674":
                    ...
                elif event_id.text == "4698":
                    ...
                elif event_id.text == "4720":
                    ...
                elif event_id.text == "4722":
                    ...
                elif event_id.text == "4740":
                    ...
                elif event_id.text == "4732":
                    ...



if __name__ == "__main__":
    parse("Security.evtx")
