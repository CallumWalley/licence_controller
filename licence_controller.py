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

# CHECKSUSER = FALSE # Disables user checks. 
# VALIDATE = FALSE # Disables validation check.
# SOAK = FALSE # Disables soak.
# LOGLEVEL = ERROR, WARNING, INFO, DEBUG

def lmutil():
    """Checks total of available licences for all objects passed"""

    feature_pattern="Users of (?P<feature_name>\w*?):  \(Total of (?P<total>\d*?) licenses issued;  Total of (?P<in_use_real>\d*?) licenses in use\)"
    licence_pattern="\s*(?P<username>\S*)\s*(?P<socket>\S*)\s*.*\), start (?P<datestr>.*)"
    cluster_pattern="mahuika.*|wbn\d{3}|wbl\d{3}|wbh\d{3}|vgpuwbg\d{3}|maui|nid00.*"
    
    # Some Servers have multiple features being tracked.
    # Consolidate licence servers to avoid making multiple calls.
    
    lmutil_list={}
    for key, value in licence_list.items():
        if not value["enabled"]:
            continue
        if not value["licence_file_path"]:
            log.error(key + " must have licence file path or address and port specified in order to check with LMUTIL")
            continue            
        if not value["licence_feature_name"]: 
            log.error(key + " must have feature specified in order to check with LMUTIL")
            continue      

        if value["server_address"] not in lmutil_list:
            lmutil_list[value["server_address"]]=[]
        lmutil_list[value["server_address"]].append(key)
    
    for key, value in lmutil_list.items():   
            
        features=list()
        lmutil_return=""


        try:
            shell_string="linx64/lmutil " + "lmstat " + " -c " + value["licence_file_path"]
            log.debug(shell_string)
            lmutil_return=subprocess.check_output(shell_string, shell=True).strip()    #Removed .decode("utf-8") as threw error.     
        except Exception as details:
            log.error("Failed to fetch " + key + " " + str(details))
            log.info("Fully soaking " + key)
            #value["token_soak"] = value["real_total"]
        else:
            for line in (lmutil_return.split("\n")):  
                feature_match = re.match(feature_pattern, line)
                licence_match = re.match(licence_pattern, line)
               
                if feature_match:
                    current_feature={"total":feature_match.groupdict()["total"], "in_use_real":feature_match.groupdict()["in_use_real"], "in_use_nesi_real":0, "users":[],"users_nesi":[]}
                    features.append({feature_match.groupdict()["feature_name"]:current_feature})
            
                if licence_match:
                    licence_row_object=licence_match.groupdict()
                    current_feature["users"].append(licence_row_object)
                    
                    if re.match(cluster_pattern, licence_row_object["socket"]):
                        current_feature["users_nesi"].append(licence_row_object)
                        current_feature["in_use_nesi_real"]+=1
            
            print(features)         
            # found=False                

            # for feature in features:
            #     if feature["feature_name"] == value["feature"]:
            #         found=True
            #         hour_index = dt.datetime.now().hour - 1
            #         value["in_use_real"] = int(feature["in_use_real"])

            #         if value["total"] != int(feature["total"]):
            #             log.warning("LMUTIL shows different total number of licences than recorded. Changing from '" + str(value["total"]) + "' to '" + feature["total"] + "'")
            #             value["total"] = int(feature["total"])

            #         # Record to running history
            #         value["history"].append(value["in_use_real"])

            #         # Pop extra array entries
            #         while len(value["history"]) > value["history_points"]:
            #             value["history"].pop(0)

            #         # Find modified in use value
            #         interesting = max(value["history"])-value["in_use_nesi"]
            #         value["soak"] = round(min(
            #             max(interesting + value["buffer_constant"], interesting * (1 + value["buffer_factor"]),0), value["total"]
            #         ))

            #         # Update average
            #         value["day_ave"][hour_index] = (
            #             round(
            #                 ((value["in_use_real"] * settings["point_weight"]) + (value["day_ave"][hour_index] * (1 - settings["point_weight"]))),
            #                 2,
            #             )
            #             if value["day_ave"][hour_index]
            #             else value["in_use_real"]
            #         )
            #     else:
            #         log.info("Untracked Feature " + feature["feature_name"] + ": " + (feature["in_use_real"]) +" of " + (feature["total"]) + "in use.")

            # if not found:
            #     log.error("Feature '" + value["feature"] + "' not found on server for '" + key + "'")

def apply_soak():

    hour_index = dt.datetime.now().hour - 1

    soak_count = ""
    log.info("╔═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╗")
    log.info("║   Licence   ║    Server   ║    Total    ║ In Use All  ║ In Use NeSI ║ Average Use ║     Soak    ║")
    log.info("╠═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╣")
    
    for key, value in licence_list.items():
        
        log.info("║" + str(value["licence_name"]).center(13) + "║" + str(value["server_name"]).center(13) + "║" + str(value["real_total"]).center(13) + "║"  + str(value["real_usage_all"]).center(13) + "║" + str(value["token_usage"]).center(13) + "║" + str(value["hourly_averages"][hour_index]).center(13) + "║" + str(value["token_soak"]).center(13) + "║")

        if value["enabled"]:
            soak_count += key + ":" + str(int(value["token_soak"])) + ","
        # Does nothing atm, idea is be able to set max total in use on cluster.
        # value.max_use
    log.info("╚═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╝")

    cluster = "mahuika"
    res_name = "licence_soak"
    # starts in 1 minute, ends in 1 year
    if slurm_permissions=="operator" or  slurm_permissions=="administrator":
        try:
            sub_input = "scontrol update -M " + cluster + " ReservationName=" + res_name + ' licenses="' + soak_count + '"'
            log.debug(sub_input)
            subprocess.check_output(sub_input, shell=True).decode("utf-8")
        except:
            log.error("Failed to update 'licence_soak' attempting to create new reservation.")
            if slurm_permissions=="administrator":
                try:
                    default_reservation = {
                        "StartTime": (dt.datetime.now() + dt.timedelta(seconds=10)).strftime(("%Y-%m-%dT%H:%M:%S")),
                        "EndTime": (dt.datetime.now() + dt.timedelta(days=365)).strftime(("%Y-%m-%dT%H:%M:%S")),
                        "Users": "root",
                        "Flags": "LICENSE_ONLY",
                    }
                    default_reservation_string = ""
                    for key, value in default_reservation.items():
                        default_reservation_string += " " + key + "=" + str(value)
                    sub_input = "scontrol create ReservationName=" + res_name + default_reservation_string + ' licenses="' + soak_count + '"'
                    log.debug(sub_input)
                    subprocess.check_output(sub_input, shell=True).decode("utf-8")
                    log.info("New reservation created successescsfully!")
                except:
                    log.error("Failed! Everything failed!")
                else:
                    log.info("Reservation updated successescsfully!")
            else:
                log.error("User does not have required SLURM permissions to create reservations.")
    else:
        log.error("User does not have required permissions to update reservations.")

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
                if licence_list[scontrol_name]["real_total"] != int(scontrol_total):
                    log.error(scontrol_name + " SCONTROL total incorrectly set!!")
                else:
                    licence_list[scontrol_name]["token_usage"] = int(scontrol_used)
            else:
                log.error("Licence " + scontrol_name + " does not exist in licence controller.")
                log.info("Empty licence " + scontrol_name + " added to meta.")
                licence_meta[scontrol_name]={}
                restart()

def restart():
    """Restarts licence controller"""
    log.info("Restarting licence controller")
    c.writemake_json(settings["path_store"], licence_list)
    c.writemake_json(settings["path_meta"], licence_meta)

    os.execl(sys.executable, sys.executable, *sys.argv)

def validate():
    """Checks for inconinosistancies"""

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
            
            if not value["license_type"] and len(key.split("@")[0].split('_'))>1:
                value["license_type"] = key.split("@")[0].split('_')[1]
                log.warning(key + " license_type set to " + value["license_type"])

            if not value["software_name"]:
                value["software_name"] = key.split("@")[0].split('_')[0]        
                log.warning(key + " software_name set to " + value["software_name"])

            if not value["licence_feature_name"] and len(key.split("@")[0].split('_'))>1:
                value["licence_feature_name"] = key.split("@")[0].split('_')[1]
                log.warning(key + " licence_feature_name set to " + value["licence_feature_name"])

            if len(key.split("@"))>1:
                if not value["institution"]:
                    value["institution"] = key.split("@")[1].split('_')[0]
                    log.warning(key + " institution set to " + value["institution"])

                if not value["faculty"] and len(key.split("@")[1].split('_'))>1:
                    value["faculty"] = key.split("@")[1].split('_')[1]
                    log.warning(key + " faculty set to " + value["faculty"])

            if not value["licence_file_group"] and value["institution"]:
                value["licence_file_group"] = value["institution"]+"-org"
                log.warning(key + " licence_file_group set to " + value["licence_file_group"])
            
            if not value["hourly_averages"] or not len(value["hourly_averages"]) == 24:
                value["hourly_averages"] = [0] * 24
                log.warning(key + " file_group set.")

            if not value["server_name"]:
                value["server_name"]=value["institution"]
                if value["faculty"]:
                    value["server_name"] += "_" + value["faculty"]
                log.warning(key + " file_group set to " + value["server_name"])

            if not value["licence_name"]:
                value["licence_name"]=value["software_name"].lower()
                if value["license_type"]:
                    value["licence_name"] += "_" + value["license_type"]
                log.warning(key + " file_group set to " + value["licence_name"])

    def _address(licence_list, licence_meta):
        for key, value in licence_list.items():

            filename_end = "_" + value["faculty"] if value["faculty"] else ""
            standard_address = "/opt/nesi/mahuika/" + value["software_name"] + "/Licenses/" + value["institution"] + filename_end + ".lic"   
            
            if value["licence_file_path"]:                
                try:
                    statdat = os.stat(value["licence_file_path"])
                    file_name = value["licence_file_path"].split("/")[-1]

                    owner = getpwuid(statdat.st_uid).pw_name
                    group = getgrgid(statdat.st_gid).gr_name

                    # Check permissions of file
                    if statdat.st_mode == 432:
                        log.error(key + " file address permissions look weird.")

                    if value["licence_file_group"] and group != value["licence_file_group"]:
                        log.error(value["licence_file_path"] + ' group is "' + group + '", should be "' + value["licence_file_group"] + '".')

                    if owner != settings["user"]:
                        log.error(value["licence_file_path"] + " owner is '" + owner + "', should be '" + settings["user"] + "'.")
                            
                    if value["licence_file_path"] != standard_address and value["software_name"] and value["institution"]:
                        log.debug('Would be cool if "' + value["licence_file_path"] + '" was "' + standard_address + '".')

                    # Read lic file contents
                    try:
                        sub_input="/bin/head -n 1 " + value["licence_file_path"]
                        log.debug(sub_input)
                        sub_out=subprocess.check_output(sub_input).decode("utf-8")
                    except Exception as details:
                        log.error("Failed to check " + key + " licence file contents at " + value["licence_file_path"] + ": " + str(details))
                    else:
                        if len(sub_out)<4:
                            log.error(key + "Licence File is missing details.")
                        else:
                            if value["server_address"] and value["server_address"]!=sub_out[1]:
                                log.error(key + " server_address does not match recorded one.")
                            if ( not value["server_address"] ) and sub_out[1]:
                                value["server_address"]=sub_out[1]
                                log.info(key + " server_address set to " + sub_out[1])

                            if value["server_host_id"] and value["server_host_id"]!=sub_out[2]:
                                log.error(key + " server_host_id does not match recorded one.")
                            if ( not value["server_host_id"] ) and sub_out[2]:
                                value["server_host_id"]=sub_out[2]
                                log.info(key + " server_host_id set to " + sub_out[2])

                            if value["server_port"] and value["server_port"]!=sub_out[3]:
                                log.error(key + " server_port does not match recorded one.")
                            if ( not value["server_port"] ) and sub_out[3]:
                                value["server_port"]=sub_out[3]
                                log.info(key + " server_port set to " + sub_out[3])            

                except Exception as details:
                    log.error(key + ' has an invalid file path attached: "' + str(details))
            else:
                value["licence_file_path"]=standard_address
                log.warning(key + " licence path set to " + standard_address)

    def _tokens(license_list):
        #Try get list of current slurm tokens
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
                if key not in active_token_dict.keys():
                    log.error("'" + key + "' does not have a token in SACCT database!")
                    if slurm_permissions=="administrator":
                        # if possible, create.
                        if value["institution"] and value["real_total"] and value["software_name"]:           
                            log.error("Attempting to add...")
                            try:
                                sub_input="sacctmgr -i add resource Name=" + value["licence_name"] + " Server=" + value["server_name"] + " Count=" + str(int(value["real_total"]*2)) + " Type=License percentallowed=50 where cluster=mahuika"
                                log.debug(sub_input)
                                subprocess.check_output(sub_input, shell=True).decode("utf-8")                         
                            except Exception as details:
                                log.error(details)
                            else:
                                log.info("Token added successfully!")         
                        else:
                            log.error("Token not created. Must have 'instituiton, software_name, cluster, real_total' set.")
                    else:
                        log.error("User does not have required SLURM permissions to add new SLURM tokens.")

                else:
                    # If total on licence server does not match total slurm tokens, update slurm tokens.
                    if value["real_total"] != int(active_token_dict[key][3])/2 and value["real_total"]!=0:
                        log.error("SLURM TOKEN BAD, HAS " + str(int(active_token_dict[key][3])/2)  + " and should be " + str(value["total"]))
                        if slurm_permissions=="operator" or slurm_permissions=="administrator":
                            try:
                                sub_input="sacctmgr -i modify resource Name=" + value["licence_name"].lower() + " Server=" + value["server_name"].lower() + " set Count=" + str(int(value["real_total"]*2))
                                log.debug(sub_input)
                                subprocess.check_output(sub_input, shell=True)        
                            except Exception as details:
                                log.error(details)
                            else:
                                log.warning("Token modified successfully!")
                        else:
                            log.error("User does not have required SLURM permissions to fix SLURM tokens totals.")

                    if active_token_dict[key][7] != "50":
                        log.error("SLURM token not cluster-split")
                        if slurm_permissions=="operator" or slurm_permissions=="administrator":
                            try:
                                sub_input="sacctmgr -i modify resource Name=" + value["licence_name"].lower() + " Server=" + value["server_name"] + "percentallocated=100 where cluster=mahuika" +  " set PercentAllowed=50"
                                log.debug(sub_input)
                                subprocess.check_output(sub_input, shell=True)

                                sub_input="sacctmgr -i modify resource Name=" + value["licence_name"].lower() + " Server=" + value["server_name"] + "percentallocated=100 where cluster=maui" +  " set PercentAllowed=50"
                                log.debug(sub_input)
                                subprocess.check_output(sub_input, shell=True)
                            except Exception as details:
                                log.error(details)
                            else:
                                log.info("Token modified successfully!")
                        else:
                            log.error("User does not have required SLURM permissions to fix SLURM tokens.")
                    
    _fill(licence_list)
    _address(licence_list, licence_meta)
    _tokens(licence_list)
    c.deep_merge(licence_meta, licence_list)

    c.writemake_json(settings["path_store"], licence_list)

def get_slurm_permssions():
    
    try:
        shell_string="sacctmgr show user ${USER} -Pn"
        log.debug(shell_string)
        lmutil_return=subprocess.check_output(shell_string, shell=True).strip().split('|')[-1].lower()    #Removed .decode("utf-8") as threw error.     
    except:
        log.error("Failed to fetch user permissions, assuming none.")
    else: 
        log.info("User SLURM permissions are '" + lmutil_return + "'")

        return lmutil_return

def main():

    looptime = time.time()

    lmutil()

    get_nesi_use()

    if os.environ["SOAK"].lower() != "false":
        apply_soak()

    c.writemake_json(settings["path_store"], licence_list)

    log.info("main loop time = " + str(time.time() - looptime))
    time.sleep((settings["poll_period"] - (time.time() - looptime)))

settings = c.readmake_json("settings.json")

log.info("Starting...")
log.info(json.dumps(settings))

slurm_permissions=get_slurm_permssions()

licence_meta = c.readmake_json(settings["path_meta"])
licence_list = c.readmake_json(settings["path_store"])

if os.environ.get("VALIDATE","").lower()=="false":
    log.info("Skipping validation")
else:
    validate()

# Is correct user
if os.environ["USER"] != settings["user"] and not os.environ.get("CHECKSUSER","").lower()=="false":
    log.error("COMMAND SHOULD BE RUN AS '" + settings["user"] + "' ELSE LICENCE STATS WONT WORK")
    exit()
while 1:
    main()