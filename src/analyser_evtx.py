#Reading evtx (Windows logs)
from Evtx.Evtx import Evtx
#Getting fields from XML
import xml.etree.ElementTree as ET

#Namespace
ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
def parse(file_path):
    global repeated_event
    with Evtx(file_path) as log:
        for record in log.records():
            xml = record.xml()
            root = ET.fromstring(xml)
            event_id = root.find(".//e:EventID",ns)
            timecreated = root.find(".//e:TimeCreated",ns).get("SystemTime")

            for process in root.findall(".//e:Data",ns):
                if process.get("Name") == "ProcessName":
                    print(f"EventID: {event_id.text}, ProcessName: {process.text}, Timecreated: {timecreated}")



if __name__ == "__main__":
    parse("../samples/Security.evtx")