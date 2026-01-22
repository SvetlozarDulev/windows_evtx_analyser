#Reading evtx (Windows logs)
from Evtx.Evtx import Evtx
#Getting fields from XML
import xml.etree.ElementTree as ET
#()init ensures colors work in Windows console; Fore - text color;
from colorama import Fore, Style

FAILED_THRESHOLD = 5
failed_logons = {}
#Namespace
ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
def parse(file_path):
    #4624:Indicates Successful authentication, 4625(Failed login):Helps detect brute force, 4776(NTLM authentication attempt): Used for detecting NTLM logins
    #4769(Kerberos service ticket granted):Identifies lateral movement using Kerberos
    #4672(Special privileges assigned):Indicates admin-level logins
    #4674(Sensitive privilege used):Detects actions requiring admin privileges
    #4698(Scheduled task created):Could indicate malware persistence
    #4720(User account created), 4722(User account enabled),4740(Account locked due to failed logins),4732(User added to admin group)
    SECURITY_EVENTS = { "4624","4625", "4776" ,"4768", "4769", "4672", "4674", "4698", "4720","4722","4740","4732" }
    with (Evtx(file_path) as log):
        for record in log.records():
            xml = record.xml()
            root = ET.fromstring(xml)
            event_id = root.find(".//e:EventID",ns)
            time_created = root.find(".//e:TimeCreated",ns).get("SystemTime")
            process_name = root.find(".//e:Data[@Name='ProcessName']",ns)
            username = root.find(".//e:Data[@Name='TargetUserName']",ns)
            user_elem = username.text if username is not None else "N/A"
            process_elem = process_name.text if process_name is not None else "No process"
            if event_id.text in SECURITY_EVENTS:
                if event_id.text == "4625":
                    failed_logons[user_elem] = failed_logons.get(user_elem,0) + 1
                    #Style.RESET_ALL - resets color after printing
                    print(f"[FAILED LOGON] EventID: {event_id.text} | TargetUserName: {user_elem} | Timecreated: {time_created} | Process: {process_elem}")
                    if failed_logons[user_elem] == FAILED_THRESHOLD:
                        print(Fore.RED + f"[ALERT] Possible BRUTE-FORCE on user {user_elem}" + Style.RESET_ALL)
                elif event_id.text == "4624":
                    ...
                elif event_id.text == "4776":
                    ...
                elif event_id.text == "4768":
                    ...
                elif event_id.text == "4769":
                    ...
                elif event_id.text == "4672":
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
