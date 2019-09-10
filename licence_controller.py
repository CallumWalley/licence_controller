# encoding: utf-8
import math, os, stat, re, json, logging, time, subprocess, sys
import datetime as dt

import common as c
from copy import deepcopy
from pwd import getpwuid
from grp import getgrgid

from common import log

#=== TO DO ===#
# Make licences on same daemon use same request.
# Check other properties
# CURRENTLY DOES NOTHING ON MAUI


def lmutil():
    """Checks total of available licences for all objects passed"""
    # This is a mess. Tidy.
    pattern="Users of (?P<feature_name>\w*?):  \(Total of (?P<total>\d*?) licenses issued;  Total of (?P<in_use_real>\d*?) licenses in use\)"
    # lmutil_list=[]
    # for key, value in licence_list.items():
    #     lmutil_list.append={"path":value["address"]}

    for key, value in licence_list.items():
        if not value["file_address"]:
            continue 
            
        if not value["feature"]: 
            log.error(key + " must have feature specified in order to check with LMUTIL")
            continue           
            
        # if value["flex_method"] == "lmutil":
        #     return
        features=[]
        lmutil_return=""
        try:
            shell_string="linx64/lmutil " + "lmstat " + "-f " + value["feature"] + " -c " + value["file_address"]
            log.debug(shell_string)
            lmutil_return=subprocess.check_output(shell_string, shell=True).strip()    #Removed .decode("utf-8") as threw error.     
        except Exception as details:
            log.error("Failed to fetch " + key + " " + str(details))
        else:
            for line in (lmutil_return.split("\n")):  
                m = re.match(pattern, line)
                if m:
                    features.append(m.groupdict())

            found=False                

            for feature in features:
                if feature["feature_name"] == value["feature"]:
                    found=True
                    hour_index = dt.datetime.now().hour - 1
                    value["in_use_real"] = int(feature["in_use_real"])

                    if value["total"] != int(feature["total"]):
                        log.warning("LMUTIL shows different total number of licences than recorded. Changing from '" + str(value["total"]) + "' to '" + feature["total"] + "'")
                        value["total"] = int(feature["total"])

                    # Record to running history
                    value["history"].append(value["in_use_real"])

                    # Pop extra array entries
                    while len(value["history"]) > value["history_points"]:
                        value["history"].pop(0)

                    # Find modified in use value
                    interesting = max(value["history"])-value["in_use_nesi"]
                    value["in_use_modified"] = round(min(
                        max(interesting + value["buffer_constant"], interesting * (1 + value["buffer_factor"])), value["total"], 0
                    ))

                    # Update average
                    value["day_ave"][hour_index] = (
                        round(
                            ((value["in_use_real"] * settings["point_weight"]) + (value["day_ave"][hour_index] * (1 - settings["point_weight"]))),
                            2,
                        )
                        if value["day_ave"][hour_index]
                        else value["in_use_real"]
                    )
                else:
                    log.info("Untracked Feature " + feature["feature_name"] + ": " + (feature["in_use_real"]) +" of " + (feature["total"]) + "in use.")

            if not found:
                log.error("Feature '" + value["feature"] + "' not found on server for '" + key + "'")

def apply_soak():

    hour_index = dt.datetime.now().hour - 1

    soak_count = ""
    log.info("╔═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╗")
    log.info("║   Licence   ║    Server   ║    Total    ║ In Use All  ║ In Use NeSI ║ Average Use ║     Soak    ║")
    log.info("╠═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╣")
    
    for key, value in licence_list.items():
        
        log.info("║" + str(key.split("@")[0].center(13)) + "║" + str(key.split("@")[1].center(13)) + "║" + str(value["total"]).center(13) + "║"  + str(value["in_use_real"]).center(13) + "║" + str(value["in_use_nesi"]).center(13) + "║" + str(value["day_ave"][hour_index]).center(13) + "║" + str(value["soak"]).center(13) + "║")


        if value["enabled"]:
            soak_count += key + ":" + str(int(value["soak"])) + ","
        # Does nothing atm, idea is be able to set max total in use on cluster.
        # value.max_use
    log.info("╚═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╝")

    cluster = "mahuika"
    res_name = "licence_soak"
    # starts in 1 minute, ends in 1 year.
    try:
        sub_input = "scontrol update -M " + cluster + " ReservationName=" + res_name + ' licenses="' + soak_count + '"'
        log.debug(sub_input)
        subprocess.check_output(sub_input, shell=True).decode("utf-8")
    except:
        log.error("Failed to update 'licence_soak' attempting to create new reservation.")
        # nesi-apps-admin doesn't have permission to do next bit.
        # try:
            # default_reservation = {
            #     "StartTime": (dt.datetime.now() + dt.timedelta(seconds=10)).strftime(("%Y-%m-%dT%H:%M:%S")),
            #     "EndTime": (dt.datetime.now() + dt.timedelta(days=365)).strftime(("%Y-%m-%dT%H:%M:%S")),
            #     "Users": "root",
            #     "Flags": "LICENSE_ONLY",
            # }
        #     default_reservation_string = ""
        #     for key, value in default_reservation.items():
        #         default_reservation_string += " " + key + "=" + str(value)
        #     sub_input = "scontrol create ReservationName=" + res_name + default_reservation_string + ' licenses="' + soak_count + '"'
        #     log.debug(sub_input)
        #     subprocess.check_output(sub_input, shell=True).decode("utf-8")
        #     log.error("New reservation created successescsfully!")
        # except:
        #     log.error("Failed! Everything failed!")
    else:
        log.info("Reservation updated successescsfully!")

def get_nesi_use():
    try:
        cluster="mahuika"
        sub_input = "scontrol -M " + cluster + " -do show licenses"
        log.debug(sub_input)
        scontrol_string=subprocess.check_output(sub_input, shell=True).decode("utf-8").strip()
    except Exception as details:
        log.error("Failed to check scontrol licence usage. " + str(details))
    else:
        scontrol_string_list=scontrol_string.split('\n')
        for line in scontrol_string_list:
            log.debug(line)

            scontrol_name = line.split(' ')[0].split('=')[1]
            scontrol_total = line.split(' ')[1].split('=')[1]
            scontrol_used = line.split(' ')[2].split('=')[1]

            if scontrol_name in licence_list.keys():
                if licence_list[scontrol_name]["total"] != int(scontrol_total):
                    log.error("THIS SHOULD NEVER HAPPEN")
                else:
                    licence_list[scontrol_name]["in_use_nesi"] = int(scontrol_used)
            else:
                log.error("Licence " + scontrol_name + " does not exist in licence controller.")
                log.info("Empty licence " + scontrol_name + " added to meta.")
                licence_meta[scontrol_name]={}
                restart()

def restart():
    """Restarts licence controller"""
    log.info("Restarting licence controller")
    c.writemake_json("licence_list.json", licence_list)
    c.writemake_json("meta/licence_meta.json", licence_meta)

    os.execl(sys.executable, sys.executable, *sys.argv)

def validate():
    """Checks for inconsistancies"""

    # Adds if licence exists in meta but not list
    for licence in licence_meta.keys():
        if not licence in licence_list:
            log.warning(licence + " is new licence. Being added to database wih default values.")
            licence_list[licence] = {}
    # Adds properties if missing from cachce (for some reason)
    for licence in licence_list.values():
        for key in settings["default"].keys():
            if key not in licence:
                licence[key] = settings["default"][key]

    def _fill(licence_list):
        """Guess at any missing properties"""
        for key, value in licence_list.items():
            
            if not value["lic_type"] and len(key.split("@")[0].split('_'))>1:
                value["lic_type"] = key.split("@")[0].split('_')[1]
                log.warning(key + " lic_type set to " + value["lic_type"])

            if not value["software_name"]:
                value["software_name"] = key.split("@")[0].split('_')[0]        
                log.warning(key + " software_name set to " + value["software_name"])

            if not value["feature"]:
                value["feature"] = key.split("@")[0].split('_')[0]
                log.warning(key + " feature set to " + value["feature"])


            if not value["institution"]:
                value["institution"] = key.split("@")[1].split('_')[0]
                log.warning(key + " institution set to " + value["institution"])


            if not value["faculty"] and len(key.split("@")[1].split('_'))>1:
                value["faculty"] = key.split("@")[1].split('_')[1]
                log.warning(key + " faculty set to " + value["faculty"])

            if not value["file_group"] and value["institution"]:
                value["file_group"] = value["institution"]+"-org"
                log.warning(key + " file_group set to " + value["file_group"])
            
            if not value["day_ave"] or not len(value["day_ave"]) == 24:
                value["day_ave"] = [0] * 24

    def _address(licence_list, licence_meta):
        for key, value in licence_list.items():

            filename_end = "_" + value["faculty"] if value["faculty"] else ""
            standard_address = "opt/nesi/mahuika/" + value["software_name"] + "/Licenses/" + value["institution"] + filename_end + ".lic"   
            
            if value["file_address"]:                
                try:
                    statdat = os.stat(value["file_address"])
                    file_name = value["file_address"].split("/")[-1]

                    owner = getpwuid(statdat.st_uid).pw_name
                    group = getgrgid(statdat.st_gid).gr_name

                    # Check permissions of file
                    if statdat.st_mode == 432:
                        log.error(key + " file address permissions look weird.")

                    if value["file_group"] and group != value["file_group"]:
                        log.error(value["file_address"] + ' group is "' + group + '", should be "' + value["file_group"] + '".')

                    if owner != settings["user"]:
                        log.error(value["file_address"] + " owner is '" + owner + "', should be '" + settings["user"] + "'.")
                              
                    if value["file_address"] != standard_address and value["software_name"] and value["institution"]:
                        log.debug('Would be cool if "' + value["file_address"] + '" was "' + standard_address + '".')

                except:
                    log.error(key + ' has an invalid file path attached "' + value["file_address"] + '"')
            else:
                value["file_address"]=standard_address
                log.warning(key + " licence path set to " + standard_address)

    def _tokens(license_list):
        try:
            sub_input="sacctmgr -pns show resource withcluster"
            log.debug(sub_input)
            string_data=subprocess.check_output(sub_input, shell=True).decode("utf-8").strip()
        except Exception as details:
            log.error("Failed to check SLURM tokens. " + str(details))
        else:
            active_token_dict = {}
            # Format output data into dictionary 
            for lic_string in string_data.split("\n"):

                log.debug(lic_string)
                str_arr=lic_string.split("|")
                active_token_dict[str_arr[0] + "@" + str_arr[1]]=str_arr


            for key, value in licence_list.items():

                name = value["software_name"] + "_" + value["lic_type"] if value["lic_type"] else value["software_name"]
                server = value["institution"] + "_" + value["faculty"] if value["faculty"] else value["institution"]

                if key not in active_token_dict.keys():
                    log.error("'" + key + "' does not have a token in slurm database!")

                    # if possible, create.
                    if value["institution"] and value["total"] and value["software_name"]:           
                        log.error("Attempting to add...")

                        try:
                            sub_input="sacctmgr -i add resource Name=" + name.lower() + " Server=" + server.lower() + " Count=" + str(int(value["total"]*2)) + " Type=License percentallowed=50 where cluster=mahuika"
                            log.debug(sub_input)
                            subprocess.check_output(sub_input, shell=True).decode("utf-8")
                            
                        except Exception as details:
                            log.error(details)
                        else:
                            log.info("Token added successfully!")
                    
                    else:
                        log.error("Must have 'instituiton, software_name, cluster, total' set in order to generate SLURM token.")

                else:
                    if value["total"] != int(active_token_dict[key][3])/2:
                        log.error("SLURM TOKEN BAD, HAS " + str(int(active_token_dict[key][3])/2)  + " and should be " + str(value["total"]))
                        try:
                            sub_input="sacctmgr -i modify resource Name=" + name.lower() + " Server=" + server.lower() + " set Count=" + str(int(value["total"]*2))
                            log.debug(sub_input)
                            subprocess.check_output(sub_input, shell=True)        
                        except Exception as details:
                            log.error(details)
                        else:
                            log.warning("Token modified successfully!")
                    if active_token_dict[key][7] != "50":
                        log.error("SLURM token not cluster-split")

                        try:
                            sub_input="sacctmgr -i modify resource Name=" + name.lower() + " Server=" + server.lower() + "percentallocated=100 where cluster=mahuika" +  " set PercentAllowed=50"
                            log.debug(sub_input)
                            subprocess.check_output(sub_input, shell=True)

                            sub_input="sacctmgr -i modify resource Name=" + name.lower() + " Server=" + server.lower() + "percentallocated=100 where cluster=maui" +  " set PercentAllowed=50"
                            log.debug(sub_input)
                            subprocess.check_output(sub_input, shell=True)
                        except Exception as details:
                            log.error(details)
                        else:
                            log.info("Token modified successfully!")
                    
    _fill(licence_list)
    _address(licence_list, licence_meta)
    _tokens(licence_list)
    c.deep_merge(licence_meta, licence_list)

def main():

    looptime = time.time()

    lmutil()
    get_nesi_use()
    apply_soak()

    c.writemake_json("licence_list.json", licence_list)

    log.info("main loop time = " + str(time.time() - looptime))
    time.sleep((settings["poll_period"] - (time.time() - looptime)))

log.info("Starting...")

settings = c.readmake_json("licence_collector_settings.json")

c.dummy_checks()

log.info(json.dumps(settings))

licence_meta = c.readmake_json("meta/licence_meta.json")
licence_list = c.readmake_json("licence_list.json")

if os.environ.get("VALIDATE")=="NO":
    log.info("Skipping validation")
else:
    validate()


# Is correct user
if os.environ["USER"] != settings["user"]:
    log.error("COMMAND SHOULD BE RUN AS '" + settings["user"] + "' ELSE LICENCE STATS WONT WORK")
    exit()
while 1:
    main()
    

# def attach_lic(licence_dat, module_dat):
#     """Attach licence info for every application"""
#     for lic, lic_value in licence_dat.items():
#         # Check if in array of licences
#         for app, app_value in module_dat.items():
#             # If same, case insensitive.

#             if app.lower() == lic_value["software"].lower():
#                 app_value["licences"][lic] = lic_value
#                 log.info("Licence " + lic + " attached to " + app)

# def validate_slurm_tokens(license_list):
#     string_data = subprocess.check_output("sacctmgr -pns show resource withcluster", stderr=subprocess.STDOUT, shell=True).decode("utf-8").strip()
#     token_list = {}

#     for lic_string in string_data.split("\n"):

#         log.debug(lic_string)

#         lic_string_array = lic_string.split("|")
#         pre_at = lic_string_array[0].split("_")
#         post_at = lic_string_array[1].split("_")

#         token = lic_string_array[0] + "@" + lic_string_array[1]
#         if "token" not in token_list:
#             token_list[token] = {}  # deepcopy(licence_primitive)
#             print("not in list")

#         token_list[token]["software"] = pre_at[0]
#         token_list[token]["institution"] = post_at[0]
#         token_list[token]["total"] = math.floor(int(lic_string_array[3]) / 2)

#         if len(pre_at) > 1:
#             token_list[token]["lic_type"] = pre_at[1]

#         if len(post_at) > 1:
#             token_list[token]["faculty"] = post_at[1]

#         token_list[token]["server_type"] = lic_string_array[5]

#         if "cluster" in token_list[token]:
#             # print('in list')

#             token_list[token]["cluster"].append(lic_string_array[6])
#         else:
#             # print('not in list')

#             token_list[token]["cluster"] = [lic_string_array[6]]

#         token_list[token]["percent"] = [lic_string_array[7]]

#     print(token_list)

#     for token_name, licence_properties in license_list.items():

#         if token_name in token_list:
#             log.info(token_name + " has asocciated slurm token ")
#             for key, value in token_list[token_name].items():

#                 if key == "percent":
#                     if value != 50:
#                         log.debug("Percent allocated should be 50% (even if not on Maui)")
#                 elif value != licence_properties[key]:
#                     log.debug("Slurm token value " + key + " is " + json.dumps(value) + "and should be" + json.dumps(licence_properties[key]))

#         else:
#             log.error(token_name + " has NO asocciated slurm token ")

#         # if "enabled" in value and value['enabled']:
#         # else:
#         #     log.info("Licence object " + key + " is disabled and will not be evaluated.")

# def update_history(licences):
# """Gets history data from previous license object"""
# prev = c.readmake_json("cache/licence_meta.json")

# for key, value in licences.items():
#     if key in prev and prev[key]["history"]:
#         value["history"] = prev[key]["history"]
# def add_new(licences):
#     for key, value in licences.items():

#  def generate_update(licences):
#     """Generates an object to pass to the licence checker"""
#     lmutil_obj = {}

#     for key, value in licences.items():
#         if value["flex_method"]:
#             if value["file_address"]:
#                 if value["file_address"] not in lmutil_obj:
#                     lmutil_obj[value["file_address"]] = []
#                 lmutil_obj[value["file_address"]].append({"feature": value["feature"], "licence": key, "count": 0})
#     return lmutil_obj

# def assign_aliases(licences):

#     aliases = c.readmake_json("cache/institutional_alias.json", {"inst": {}, "fac": {}})
#     for key, value in licences.items():

#         if value["institution"] in aliases["inst"]:
#             value["institution_alias"] = aliases["inst"][value["institution"]]

#         if value["faculty"] in aliases["fac"]:
#             value["faculty_alias"] = aliases["fac"][value["faculty"]]

#   string_data = subprocess.check_output("sacctmgr -pns show resource withcluster", stderr=subprocess.STDOUT, shell=True).decode("utf-8").strip()

#         for lic_string in string_data.split("\n"):

#             log.debug(lic_string)

#             lic_string_array = lic_string.split("|")
#             pre_at = lic_string_array[0].split("_")
#             post_at = lic_string_array[1].split("_")

#             token = lic_string_array[0] + "@" + lic_string_array[1]
#             if "token" not in token_list:
#                 token_list[token] = {}  # deepcopy(licence_primitive)
#                 log.error()

#             token_list[token]["software"] = pre_at[0]
#             token_list[token]["institution"] = post_at[0]
#             token_list[token]["total"] = math.floor(int(lic_string_array[3]) / 2)

#             if len(pre_at) > 1:
#                 token_list[token]["lic_type"] = pre_at[1]

#             if len(post_at) > 1:
#                 token_list[token]["faculty"] = post_at[1]

#             token_list[token]["server_type"] = lic_string_array[5]

#             if "cluster" in token_list[token]:
#                 # print('in list')

#                 token_list[token]["cluster"].append(lic_string_array[6])
#             else:
#                 # print('not in list')

#                 token_list[token]["cluster"] = [lic_string_array[6]]

#             token_list[token]["percent"] = [lic_string_array[7]]

#         print(token_list)
#     except:
#         log.error("Failed to check SLURM tokens")
