# encoding: utf-8
import math, os, stat, re, json, logging, time, subprocess, sys
import datetime as dt

import common as c
from copy import deepcopy
from pwd import getpwuid
from grp import getgrgid
from common import log

#=== TO DO ===#
# CHECKUSER = FALSE # Disables user checks. 
# VALIDATE = FALSE # Disables validation check.
# SOAK = FALSE # Disables soak.
# LOGLEVEL = ERROR, WARNING, INFO, DEBUG

# cmd_method=<command line argument to get output>
# licence_pattern=<pattern applied to extract indiviudal licence users>
# server_pattern=<pattern applied to get global server properties>


poll_methods={
    "ansysli_util":{
        "shell_command":"export ANSYSLMD_LICENSE_FILE=$(head -n 1 %(licence_file_path)s | sed -n -e 's/.*=//p');linx64/ansysli_util -liusage",
        "licence_pattern":"(?<user>[A-Za-z0-9]*)@(?<host>\S*)\s*(?<date>[\d\/]*?) (?<time>[\d\:]*)\s*(?<feature>[\S^\d]*)[^\d]*(?<count>\d*)\s*(?<misc>.*)", 
        "server_pattern":""
    },
    "lmutil":{
        "shell_command":"linx64/lmutil lmstat -a -c %(licence_file_path)s",
        "licence_pattern":"^.*\"(?<feature>\S+)|\".|\\n*^\s*(?<user>\S*).*\((?<host>\S*) \d*\).* (?<date>\d+\/\d+) (?<time>[\d\:]+).*$",
        "server_pattern":""
    }
}

def init_polling_object():
    # Some Servers have multiple features being tracked.
    # Consolidate licence servers to avoid making multiple calls.
    
    log.info("Constructing polling object...")
    # Just for info
    server_count=0
    feature_count=0

    for key, value in licence_list.items():

        # if not value["active"]:
        #     log.error("a")
        #     continue
        # if not value["enabled"]:
        #     log.error("b")
        #     continue
        if not value["licence_file_path"]:
            log.error(key + " must have licence file path or address and port specified in order to check with LMUTIL")
            continue            
        if not value["licence_feature_name"]: 
            log.error(key + " must have feature specified in order to check with LMUTIL")
            continue
        if not value["server_poll_method"] in poll_methods.keys(): 
            log.error(key + " must have poll method specified in order to check with LMUTIL")
            continue
        if not value["server_address"]: 
            log.error(key + " must have address specified in order to check with LMUTIL")
            continue

        if value["server_address"] not in poll_list:
            poll_list[value["server_address"]]={"licence_file_path":value["licence_file_path"], "server_poll_method":value["server_poll_method"], "tokens":[]}
            server_count+=1
        feature_count+=1
        poll_list[value["server_address"]]["tokens"].append(value)
    log.info(str(server_count) + " servers being polled for " + str(feature_count) + " licence features.")


def poll():
    """Checks total of available licences for all objects passed"""
        

    # log.info("Checking FlexLM servers...")

    # feature_pattern=re.compile(r"Users of (?P<feature_name>\w*?):  \(Total of (?P<total>\d*?) licenses issued;  Total of (?P<in_use_real>\d*?) licenses in use\)")
    # licence_pattern=re.compile(r"\s*(?P<username>\S*)\s*(?P<socket>\S*)\s*.*\), start (?P<datestr>.*?:.{2}).?\s?(?P<count>\d)?.*")
    # server_pattern=re.compile(r".*license server (..)\s.*")

    # cluster_pattern=re.compile(r"mahuika.*|wbn\d{3}|wbl\d{3}|wbh\d{3}|vgpuwbg\d{3}|maui|nid00.*")
    for key, value in poll_list.items():              
        log.debug("Checking Licence Server at '" + key + "'...")

        # Should be able to remove this check 
        if value["server_poll_method"] not in poll_methods:
            log.error("Unknown poll method '" + value["server_poll_method"] + "'")

        
        shell_command_string=poll_methods[value["server_poll_method"]]["shell_command"] % value
        log.debug(shell_command_string)
        try:
            sub_return=subprocess.check_output(shell_command_string, shell=True)    #Removed .decode("utf-8") as threw error.     
            #print(sub_return)

            features=re.search(poll_methods[value["server_poll_method"]]["licence_pattern"], sub_return).groupdict()
            # Create object from output.
            print(features)

            # # Rather than for loop, this could be done in 1 call of regex engine.
            for licence in features:
                x=1
            #     feature_match = feature_pattern.match(line)
            #     licence_match = licence_pattern.match(line)
            #     server_match = server_pattern.match(line)

            #     if server_match:
            #         server_status=server_match.group(1)

            #     if feature_match:
            #         current_feature={"server_status":server_status, "real_total":int(feature_match.groupdict()["total"]), "real_usage_all":int(feature_match.groupdict()["in_use_real"]), "real_usage_nesi":0, "users_nesi":[]}
            #         features[feature_match.groupdict()["feature_name"]]=current_feature
            
            #     if licence_match:
            #         licence_row_object=licence_match.groupdict()

            #         current_feature["users"].append(licence_row_object)

            #         if cluster_pattern.match(licence_row_object["socket"]):
            #             current_feature["users_nesi"].append(licence_row_object)
            #             if licence_row_object["count"]:
            #                 current_feature["real_usage_nesi"]+=int(licence_row_object["count"])
            #             else:
            #                 current_feature["real_usage_nesi"]+=1
            #     # Assign any tracked features
            #     for token in value["tokens"]:
            #         token.update(features[token["licence_feature_name"]])
                
            #     log.info("Licence Server at '" + key + "' " + server_status)
        except Exception as details:
            log.error("Failed to fetch " + key + " " + str(details))
            #log.info("Fully soaking " + key)
            #value["token_soak"] = value["real_total"]
            for token in value["tokens"]:
                token["server_status"]="FAIL"
            log.info("\rLicence Server at '" + key + "' FAIL")

def do_maths():    
    
    log.info("Doing maths...")
    for key, value in licence_list.items():
        hour_index = dt.datetime.now().hour - 1

        if not value['enabled']:
            continue

        # Record to running history
        value["history"].append(value["real_usage_all"])

        # Pop extra array entries
        while len(value["history"]) > value["history_points"]:
            value["history"].pop(0)

        # Find modified in use value
        interesting = max(value["history"])-value["token_usage"]

        if not value['active']:
            value["token_soak"]=value["real_total"]
        else:
            value["token_soak"] = int(min(
                max(interesting + value["buffer_constant"], interesting * (1 + value["buffer_factor"]),0), value["real_total"]
            ))

        # Update average
        value["hourly_averages"][hour_index] = (
            round(
                ((value["real_usage_all"] * settings["point_weight"]) + (value["hourly_averages"][hour_index] * (1 - settings["point_weight"]))),
                2,
            )
            if value["hourly_averages"][hour_index]
            else value["real_usage_all"]
        )

def apply_soak():

    def _update_res(cluster):

        sub_input = "scontrol update -M " + cluster + " ReservationName=" + res_name + ' EndTime=' + endtime + " " + soak_count
        log.debug(sub_input)

        if not (slurm_permissions=="operator" or  slurm_permissions=="administrator"):
            raise Exception("User does not have appropriate SLURM permissions to run '" + sub_input+ "'")
        
        subprocess.check_output(sub_input, shell=True).decode("utf-8")

    def _create_res(cluster):
            sub_input = "scontrol create -M " + cluster + " ReservationName=" + res_name + " StartTime=" + starttime + " EndTime=" + endtime +  " Users=root Flags=LICENSE_ONLY " + soak_count

            if slurm_permissions!="administrator":          
                raise Exception("User does not have appropriate SLURM permissions to run '" + sub_input + "'")

            log.debug(sub_input)
            subprocess.check_output(sub_input, shell=True).decode("utf-8")

    if os.environ.get("SOAK","").lower() == "false":
        log.info("Licence Soak skipped due to 'SOAK=FALSE'")
        return

    log.info("Applying soak...")
    res_name = "licence_soak"
    starttime=(dt.datetime.now() + dt.timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%S")
    endtime=(dt.datetime.now() + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    soak_count=""

    for key, value in licence_list.items():
        if not (value["enabled"] and value["active"] and value["token_soak"]):
            continue
        soak_count += key + ":" + str(value["token_soak"]) + ","

    if soak_count:
        soak_count=' licenses=' + soak_count
    try:
        _update_res("mahuika")
    except Exception as details:
        log.error("Reservation update failed: " + str(details))
        log.info("Attempting to create new reservation.")
        try: 
            _create_res("mahuika")
        except Exception as details:
            log.error("Failed to create reservation: " + str(details))
        else:
            log.info("New reservation '" + res_name + "' created successfully.")

    else:
        log.info("Reservation updated successfully!")

def print_panel():
    hour_index = dt.datetime.now().hour - 1

    log.info("╔═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╗")
    log.info("║   Licence   ║    Server   ║    Status   ║    Total    ║ In Use All  ║ Average Use ║ In Use NeSI ║  Token Use  ║     Soak    ║")
    log.info("╠═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╣")
    
    for key, value in licence_list.items():
        if value["active"]:
            log.info("║" + str(value["licence_name"]).center(13) + "║" + str(value["server_name"]).center(13) + "║" + str(value["server_status"]).center(13) + "║" + str(value["real_total"]).center(13) + "║"  + str(value["real_usage_all"]).center(13) + "║"  + str(value["hourly_averages"][hour_index]).center(13) + "║" + str(value["real_usage_nesi"]).center(13) + "║" + str(value["token_usage"]).center(13) + "║" + str(value["token_soak"]).center(13) + "║" )

        
    log.info("╚═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╩═════════════╝")

def get_nesi_use():

    log.info("Checking NeSI tokens...")
    all_licence_string=""

    for key in licence_list.keys():
        all_licence_string+=key + ","

    if not all_licence_string:
        return

    # Search squeue for running or pending jobs
    cluster="mahuika"
    sub_input = "squeue -h -M " + cluster + " --format=\"%u|%C|%t|%r|%S|%N|%W\" -L " + all_licence_string
    
    #licence_pattern=re.compile(r"\s*(?P<username>\S*)\s*(?P<socket>\S*)\s*.*\), start (?P<datestr>.*?:.{2}).?\s?(?P<count>\d)?.*")
    log.debug(sub_input)

    try:
        scontrol_string=subprocess.check_output(sub_input, shell=True).decode("utf-8").strip()
    except Exception as details:
        log.error("Failed to check scontrol licence usage. " + str(details))
    else:
        # Set current usage to zero
        for licence in licence_list.keys():
            licence_list[licence]["token_usage"]=0

        # Read by line
        scontrol_string_list=scontrol_string.split('\n')
        scontrol_string_list.pop(0) # First Line is bleh

        for line in scontrol_string_list:
            log.debug(line+"\n")
            line_delimited=line.split('|')
            licences_per_user=line_delimited[6].split(',')
            # User may have multiple licences. Proccess for each.
            for licence_on_user in licences_per_user:
                licence_on_user_count=licence_on_user.split(':')[1]
                licence_on_user_name=licence_on_user.split(':')[0]

                if licence_on_user_name in licence_list.keys():
                    licence_list[licence_on_user_name]["token_usage"] += int(licence_on_user_count)
                    # Add user info here


                    # Yea
                else:
                    log.error("Licence " + licence_on_user_name + " does not exist in licence controller.")
                    log.info("Empty licence " + licence_on_user_name + " added to meta.")
                    licence_meta[licence_on_user_name]={}
                    restart()

def restart():
    """Restarts licence controller"""
    log.info("Restarting licence controller...")
    c.writemake_json(settings["path_store"], licence_list)
    c.writemake_json(settings["path_meta"], licence_meta)

    os.execl(sys.executable, sys.executable, *sys.argv)

def validate():
    """Checks for inconinosistancies"""

    if os.environ.get("VALIDATE","").lower()=="false":
        log.info("Skipping validation")
        return

    log.info("Validating licence dictionary...")

    # Adds if licence exists in meta but not list
    for licence in licence_meta.keys():
        if not licence in licence_list:
            log.warning(licence + " is new licence. Being added to database wih default values.")
            licence_list[licence] = {}
    # Adds properties if missing from cachce (for some reason)
    for licence in licence_list.values():
        # Add missing values
        for key in settings["default"].keys():
            if key not in licence:
                licence[key] = settings["default"][key]
        for key in licence.keys():
            if key not in settings["default"]:
                log.warning("Removed defunct key '" + key + "' from something" )
                licence.pop(key)
        
        


        # Remove extra


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

            if not value["token_name"]:
                value["token_name"]=key
                log.warning(key + " token_name set to " + value["token_name"])

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
                        with open(value["licence_file_path"]) as file:
                            sub_out = file.readline().split()
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
        # Try to fix a token if incorrect.
        def __update_token_count():

            log.info("Attempting to modify SLURM token " + key)

            if not (value["institution"] and value["real_total"] and value["software_name"]):         
                raise Exception("Token not created. Missing one or more of 'instituiton', 'software_name', 'real_total'.")               
            
            sub_input="sacctmgr -i modify resource Name=" + value["licence_name"] + " Server=" + value["server_name"] + " set Count=" + str(correct_count)

            if not (slurm_permissions=="operator" or  slurm_permissions=="administrator"):
                raise Exception("User does not have appropriate SLURM permissions to run '" + sub_input + "'")

            log.debug(sub_input)
            subprocess.check_output(sub_input, shell=True).decode("utf-8")

            time.sleep(5)

        def __update_token_share(cluster):

            log.info("Attempting to modify SLURM token " + key + " for " + cluster)

            if not (value["institution"] and value["real_total"] and value["software_name"]):         
                raise Exception("Token not created. Missing one or more of 'instituiton', 'software_name', 'real_total'.")               
            
            sub_input="sacctmgr -i modify resource Name=" + value["licence_name"] + " Server=" + value["server_name"] +  " set percentallowed=" + str(correct_share) + " where cluster=" + cluster

            if not (slurm_permissions=="operator" or  slurm_permissions=="administrator"):
                raise Exception("User does not have appropriate SLURM permissions to run '" + sub_input + "'")

            log.debug(sub_input)
            subprocess.check_output(sub_input, shell=True).decode("utf-8")
            time.sleep(5)

        #Try to create  a token if missing.
        def __create_token(cluster):
            log.info("Attempting to create SLURM token " + key + " for " + cluster)

            if not (value["institution"] and value["real_total"] and value["software_name"]):         
                raise Exception("Token not created. Missing one or more of 'instituiton', 'software_name', 'real_total'.")               

            sub_input="sacctmgr -i add resource Name=" + value["licence_name"] + " Server=" + value["server_name"] + " Count=" + str(correct_count) + " Type=License percentallowed=" + str(correct_share) +" where cluster=" + cluster

            if slurm_permissions!="administrator":          
                raise Exception("User does not have appropriate SLURM permissions to run '" + sub_input + "'")

            log.debug(sub_input)
            subprocess.check_output(sub_input, shell=True).decode("utf-8")
            time.sleep(5)

        try:
            sub_input="sacctmgr -pns show resource withcluster"
            log.debug(sub_input)
            string_data=subprocess.check_output(sub_input, shell=True).decode("utf-8").strip()
        except Exception as details:
            log.error("Failed to check SLURM tokens. " + str(details))
        else:
            active_token_dict = {}

            
            #log.info("Tokens being divided between " + str(number_clusters) + " clusters.")

            # Format output data into dictionary 
            for lic_string in string_data.split("\n"):

                log.debug(lic_string)
                str_arr=lic_string.split("|")
                active_token_dict[str_arr[0] + "@" + str_arr[1]]=str_arr

            for key, value in licence_list.items():


                # SLURM requires that each cluster is given a fraction of the full licence pool. 
                # In order to allow ALL clusters full access to the pool the total number of licence is set at <# clusters> * actual licence count.
                # However this means if multiple pulls of tokens are made across 2 clusters SLURM will be suprised when the licence tracker catches up with the token count.
                # TO IMPLIMENT
                # Temporary allocations need to be made to correspond to scheduled licence useage on other cluster.

                number_clusters=len(value["clusters"])
                
                correct_share=int(100/number_clusters)
                correct_count=value["real_total"] *  number_clusters
                log.info("Licence '" + key + "' is in use on " + str(number_clusters) + " cluster(s) ( " + (", ".join(value["clusters"])) + " ).")

                if key not in active_token_dict.keys():
                    log.error(key + " not in SACCT database. Attempting to add.")
                    try:
                        for cluster in settings["clusters"]:
                            __create_token(cluster)
                    except Exception as details:
                        log.info("Disabling licence " + key + ".")

                        log.info("Disabling licence " + key + ".")

                        value["enabled"]=False
                        value["server_status"]="NULL_TOKEN"                    
                    else:
                        log.info("SLURM token successfully added.")

                    continue

                actual_count=int(active_token_dict[key][3])
                actual_share=int(active_token_dict[key][7])
                cluster=active_token_dict[key][6]

                if correct_share != actual_share:
                    log.error(key + " has cluster share incorrectly set in SACCT database ( '" + str(actual_share) +  "' should be '" + str(correct_share) + "'). Attempting to fix.")
                    try:
                        for cluster in value["clusters"]:
                            __update_token_share(cluster)
                    except Exception as details:
                        log.error("Failed to update SLURM token: " + str(details))
                        log.info("Disabling licence " + key + ".")

                        value["enabled"]=False
                        value["server_status"]="SELFISH_TOKEN"
                    else:
                        log.info("SLURM token successfully updated.")

                    continue

                if correct_count != actual_count:
                
                    log.error(key + " has count incorrectly set in SACCT database. Attempting to fix.")
                    try:
                        __update_token_count()
                    except Exception as details:
                        log.error("Failed to update SLURM token: " + str(details))
                        log.info("Disabling licence " + key + ".")

                        value["enabled"]=False
                        value["server_status"]="WRONG_TOKEN"
                    else:
                        log.info("SLURM token successfully updated.")

                    continue
                
                if actual_count==0:
                    value["enabled"]=False
                    value["server_status"]="ZERO_TOKEN"

                    log.error(key + " has 0 tokens in slurm db. Disabling.")
                    continue

                    # else:
                    #     If total on licence server does not match total slurm tokens, update slurm tokens.
                    #     if value["real_total"] != int(active_token_dict[key][3])/2 and value["real_total"]!=0:
                    #         log.error("SLURM TOKEN BAD, HAS " + str(int(active_token_dict[key][3])/2)  + " and should be " + str(value["total"]))
                    #         if slurm_permissions=="operator" or slurm_permissions=="administrator":
                    #             try:
                    #                 sub_input="sacctmgr -i modify resource Name=" + value["licence_name"].lower() + " Server=" + value["server_name"].lower() + " set Count=" + str(int(value["real_total"]*2))
                    #                 log.debug(sub_input)
                    #                 subprocess.check_output(sub_input, shell=True)        
                    #             except Exception as details:
                    #                 log.error(details)
                    #             else:
                    #                 log.warning("Token modified successfully!")
                    #         else:
                    #             log.error("User does not have required SLURM permissions to fix SLURM tokens totals.")

                    #     if active_token_dict[key][7] != "50":
                    #         log.error("SLURM token not cluster-split")
                    #         if slurm_permissions=="operator" or slurm_permissions=="administrator":
                    #             try:
                    #                 sub_input="sacctmgr -i modify resource Name=" + value["licence_name"].lower() + " Server=" + value["server_name"] + " percentallocated=100 where cluster=mahuika" +  " set PercentAllowed=50"
                    #                 log.debug(sub_input)
                    #                 subprocess.check_output(sub_input, shell=True)

                    #                 sub_input="sacctmgr -i modify resource Name=" + value["licence_name"].lower() + " Server=" + value["server_name"] + " percentallocated=100 where cluster=maui" +  " set PercentAllowed=50"
                    #                 log.debug(sub_input)
                    #                 subprocess.check_output(sub_input, shell=True)
                    #             except Exception as details:
                    #                 log.error(details)
                    #             else:
                    #                 log.info("Token modified successfully!")
                    #         else:
                    #             log.error("User does not have required SLURM permissions to fix SLURM tokens.")

    def _clusters(licence_list, module_list):
        print("Checking clusters")

        for module, module_value in module_list["modules"].items():
            
            for licence_key, licence_value in licence_list.items():
                if licence_value["software_name"].lower() == module.lower():
                    log.debug(licence_key +" exists as module")
                    log.debug(",".join(module_value["machines"]))
                    for cluster in module_value["machines"].keys():
                        if cluster not in licence_value["clusters"]:
                            licence_value["clusters"].append(cluster.lower())
                            log.info(cluster.lower() + " added to " + licence_key )
            
    _clusters(licence_list, module_list)
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

    poll()
    return
    get_nesi_use()
    
    do_maths()
     
    apply_soak()

    print_panel()
    #print(json.dumps(licence_list))
    c.writemake_json(settings["path_store"], licence_list)

    
settings = c.readmake_json("settings.json")
module_list = c.readmake_json(settings["path_modulelist"])

log.info("Starting...")
slurm_permissions=get_slurm_permssions()

# Is correct user
if os.environ["USER"] != settings["user"] and not os.environ.get("CHECKUSER","").lower()=="false":
    log.error("Command should be run as '" + settings["user"] + "' as it owns licence files. ('export CHECKUSER=FALSE' to disable this check)")
    exit()

log.debug(json.dumps(settings))

licence_meta = c.readmake_json(settings["path_meta"])
licence_list = c.readmake_json(settings["path_store"])

validate()
poll_list={}
init_polling_object()

while 1:
    looptime = time.time()
    try:
        main()
    except Exception as details:
        log.error("Main loop failed: " + str(details))

    log.info("main loop time = " + str(time.time() - looptime))
    time.sleep(max(settings["poll_period"] - (time.time() - looptime), 0))

    # for key, value in licence_list.items():
    # hour_index = dt.datetime.now().hour - 1
    # value["in_use_real"] = int(feature["in_use_real"])

    # if value["total"] != int(feature["total"]):
    #     log.warning("LMUTIL shows different total number of licences than recorded. Changing from '" + str(value["total"]) + "' to '" + feature["total"] + "'")
    #     value["total"] = int(feature["total"])

    # # Record to running history
    # value["history"].append(value["in_use_real"])

    # # Pop extra array entries
    # while len(value["history"]) > value["history_points"]:
    #     value["history"].pop(0)

    # # Find modified in use value
    # interesting = max(value["history"])-value["in_use_nesi"]
    # value["soak"] = round(min(
    #     max(interesting + value["buffer_constant"], interesting * (1 + value["buffer_factor"]),0), value["total"]
    # ))

    # # Update average
    # value["day_ave"][hour_index] = (
    #     round(
    #         ((value["in_use_real"] * settings["point_weight"]) + (value["day_ave"][hour_index] * (1 - settings["point_weight"]))),
    #         2,
    #     )
    #     if value["day_ave"][hour_index]
    #     else value["in_use_real"]
    # )