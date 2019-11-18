import os
import json
import requests
import logging
import datetime
import subprocess
import requests


def init_logger(path):
    
    # ===== Log Stuff =====#
    log_path = path
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    # Log Info to console USE ENV VARIABLE LOGLEVEL TO OVERRIDE
    console_logs = logging.StreamHandler()
    console_logs.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    try:
        console_logs.setLevel(os.environ.get("LOGLEVEL", "INFO"))
    except Exception as thing:
        console_logs.setLevel("INFO")
    
    log.addHandler(console_logs)

    # Log warnings and above to text file.
    file_logs = logging.FileHandler(log_path)
    file_logs.setLevel("WARNING")
    file_logs.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

    log.addHandler(file_logs)

    return log

def post_kafka(topic, outject):
    

    headers = {
        'Content-Type': 'application/vnd.kafka.json.v2+json',
        'Accept': 'application/vnd.kafka.v2+json',
    }
    data = json.dumps({"records":[{"value":outject}]})
    response = requests.post('https://hpcwprojects05.dev.mahuika.nesi.org.nz:10002/topics/' + topic, headers=headers, data=data, verify=False)
 
    if response.status_code == 200: 
        log.info("POST to Kafka successful!") 
        return 0
    else:
        log.error("POST to Kafka failed: " +  str(response.content))
        return 1
        
def pull(address):
    request = requests.get(address)
    if request.status_code == 200:
        try:
            out_dict = request.json()
            return out_dict
        except:
            log.error("Failed to convert request from " + address +
                      " to dictionary.")
            log.debug(str(request.content))
    else:
        log.error("Failed to pull from " + str(address))# + " (" + str(request.status_code) + ").")
    return
#Read file at {path}. If not exist make one with {default} value

def readmake_json(path, default={}):
    """Reads and returns JSON file as dictionary, if none exists one will be created with default value."""
    if not os.path.exists(path):
        log.error("No file at path '" + path + "'.")
        with open(path, "w") as json_file:
            json_file.write(json.dumps(default))
        log.error("Empty file created")

    with open(path) as json_file:
        log.info(path + " loaded.")
        return json.load(json_file)

def writemake_json(path, outject):
    with open(path, "w+") as json_file:
        json_file.write(json.dumps(outject))
        log.info(path + " updated")

def assign_tags(module_dat, tag_field, tags):

    for tag, apps in tags.items():
        for app in apps:
            if app in module_dat:
                # if tag_field module_dat[app]:
                    # If list, append
                if isinstance(module_dat[app][tag_field], list):
                    if not tag in module_dat[app][tag_field]:
                        module_dat[app][tag_field].append(tag)
                        module_dat[app][tag_field].sort()
                # Else overwrite
                else:
                    module_dat[app][tag_field] = tag

            else:
                log.warning(
                    "Error! tag '" + app + "' does not correspond to a application on the platform.")

def deep_merge(over, under, write_log=False):
    """Deep merges dictionary
    If conflict 'over' has right of way"""
    diff_log = ""
    #now=datetime.datetime.now()
    # Returns difference if write log true
    for key, value in over.items():
    
        if not value:
            log.debug(key + ": no changes to make.")
        elif key in under:
            log.debug( json.dumps(under[key]) + " ==> " + json.dumps(value))
            # If match, ignore.

            if under[key] == value:
                log.debug(key + ": no changes to make.")
                #If evaluates false, replace.
            elif not under[key]:
                
                log.debug("Property '" + key + "' SET to " + json.dumps(value))
                if write_log:
                    diff_log += ("Property '" + key +
                                              "' SET to " + json.dumps(value) +
                                              "\n")
                    log.info("Change written to log")
                under[key]=value
            # If (non-zero) dictionary
            elif isinstance(value, dict):
                # If dict key exists in both, we need to go deeper.

                log.debug("Inside " + key + "...\n")
                node = under.setdefault(key, {})
                deep_merge(value, node, write_log)

            # Lists
            elif isinstance(value, list):
                #For each member of list
                for thing in value:
                    #Not duplicate
                    if not thing in under[key]:                    
                        log.debug("Property '" + key + "' appended with '" +
                                  json.dumps(thing) + "'")
                        if write_log:
                            diff_log += ("Property '" + key +
                                                      "' appended with '" +
                                                      json.dumps(thing) +
                                                      "'\n")
                            log.info("Change written to log")
                        under[key].append(thing)
            else:
                # Value replaced
                log.debug("case 5")
                log.debug("Property '" + key + "' CHANGED from '" + json.dumps(under[key]) +
                         "' to '" + json.dumps(value) + "'")
                if write_log:
                    diff_log += ("Property '" + key +
                                              "' CHANGED from '" + json.dumps(under[key]) +
                                              "' to '" + json.dumps(value) + "'\n")
                    log.debug("Change written to log")
                under[key] = value
        else:
            # Set key equal to value
            log.debug("Property " + key + " SET to " + json.dumps(value))
            if write_log:
                diff_log += ("Property " + key + " SET to " +
                                          json.dumps(value))
                log.debug("Change written to log")
            under[key] = value
    
    return diff_log

def dummy_checks():
        # Folders exist?
    if not os.path.exists("meta"):
        log.warning("Creating missing directory 'meta'")
        os.makedirs("meta")
    if not os.path.exists("cache"):
        log.warning("Creating missing directory 'cache'")
        os.makedirs("cache")

    # # On mahuika?
    # if not (socket.gethostname().startswith("mahuika")):
    #     log.error("Currently must be run from Mahuika. Because I am lazy.")
    #     return 1
    
log=init_logger("warn.logs")
