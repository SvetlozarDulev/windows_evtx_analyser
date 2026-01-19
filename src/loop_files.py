import os
from analyser_evtx import security_parse, application_parse, system_parse, setup_parse

os.chdir(r"C:\Windows\System32\winevt\Logs")

for file in os.listdir(os.getcwd()):
    if file == "Application.evtx":
        application_parse("Application.evtx")
    elif file == "Security.evtx":
        security_parse("Security.evtx")
    elif file == "System.evtx":
        system_parse("System.evtx")
    elif file == "Setup.evtx":
        setup_parse("Setup.evtx")
