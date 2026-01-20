#Reading evtx (Windows logs)
from Evtx.Evtx import Evtx
#Getting fields from XML
import xml.etree.ElementTree as ET

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
    with Evtx(file_path) as log:
        for record in log.records():
            xml = record.xml()
            root = ET.fromstring(xml)
            event_id = root.find(".//e:EventID",ns)
            time_created = root.find(".//e:TimeCreated",ns).get("SystemTime")
            process_name = root.find(".//e:Data[@Name='ProcessName']",ns)
            process_elem = process_name.text if process_name is not None else "No process"
            if event_id.text in SECURITY_EVENTS:
                print(f"EventID: {event_id.text} | Timecreated: {time_created} | Process: {process_elem}")

if __name__ == "__main__":
    parse("Security.evtx")
