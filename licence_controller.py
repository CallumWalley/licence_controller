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


# 'enabled' = If 'false' licence server will not be checked, reservation will not be updated. Toggled off if licence is lacking required property.
# 'active' = If false 'soak' will be set to 'total'. toggled off if licence server cannnot be reached during runtime.


# Identifies whether NeSI host.
cluster_pattern=re.compile(r".*mahuika.*|.*maui.*|.*lander.*|.*nesi.*|wbn\d{3}|wcl\d{3}|vgpuwbg\d{3}|wbl\d{3}|wbh\d{3}|nid00\d{3}|wsn\d{3}|vgpuwsg\d{3}", flags=re.I)
poll_methods={
    "ansysli_util":{
        "shell_command":"export ANSYSLMD_LICENSE_FILE=$(head -n 1 %(licence_file_path)s | sed -n -e 's/.*=//p');linx64/ansysli_util -liusage",
        "licence_pattern":re.compile(r"(?P<user>[A-Za-z0-9]*)@(?P<host>\S*)\s*(?P<date>[\d\/]*?) (?P<time>[\d\:]*)\s*(?P<feature>[\S^\d]*)[^\d]*(?P<count>\d*)\s*(?P<misc>\S*)",flags=re.M), 
        "server_pattern":"",
        "details_pattern":re.compile(r"SERVER=(?P<server_port>\d*)@(?P<server_address>\S*)")
    },
    "lmutil":{
        "shell_command":"linx64/lmutil lmstat -a -c %(licence_file_path)s",
        "licence_pattern":re.compile(r"^.*\"(?P<feature>\S+)\".|\n*^\s*(?P<user>\S*)\s*(?P<host>\S*).*\s(?P<date>\d+\/\d+)\s(?P<time>[\d\:]+).*$",flags=re.M),
        "server_pattern":"",
        "details_pattern":re.compile(r"SERVER\s+(?P<server_address>\S*)\s+(?P<server_>\d*|ANY)\s(?P<server_port>[\d|,]*)")
    },
    "null":{
        "shell_command":"",
        "licence_pattern":"",
        "server_pattern":""
    }
}
untracked={}

def ex_slurm_command(sub_input, level="administrator"):
    log.debug("Attempting to run SLURM command '" + sub_input + "'.")
    if (level=="administrator" and slurm_permissions=="administrator") or (level=="operator" and (slurm_permissions=="operator" or slurm_permissions=="administrator")):
        try:
            output=subprocess.check_output(sub_input, shell=True).decode("utf-8")
        except Exception as details:
            raise Exception("Failed to execute SLURM command '"+ sub_input + "':" + str(details))   
        else:
            log.debug("Success!")
            time.sleep(5) #Avoid spamming database
            return output
    else:
        
        with open("run_as_admin.sh","a+") as f:
            f.write(sub_input+"\n")
        log.error("Writing command to 'run_as_admin.sh'")

        raise Exception("User does not have appropriate SLURM permissions to run this command.")

def init_polling_object():
    # Some Servers have multiple features being tracked.
    # Consolidate licence servers to avoid making multiple calls.
    
    log.info("Constructing polling object...")
    # Just for info
    server_count=0
    feature_count=0

    for key, ll_value in licence_list.items():
        if not ll_value['enabled']:
            continue
        if ll_value["server_address"] not in poll_list:
            poll_list[ll_value["server_address"]]={"licence_file_path":ll_value["licence_file_path"], "server_poll_method":ll_value["server_poll_method"], "tokens":[]}
            server_count+=1
        feature_count+=1
        poll_list[ll_value["server_address"]]["tokens"].append(ll_value)
    log.info(str(server_count) + " servers being polled for " + str(feature_count) + " licence features.")

def poll():
    """Checks total of available licences for all objects passed"""
        
    log.info("Polling...")

    # feature_pattern=re.compile(r"Users of (?P<feature_name>\w*?):  \(Total of (?P<total>\d*?) licenses issued;  Total of (?P<in_use_real>\d*?) licenses in use\)")
    # licence_pattern=re.compile(r"\s*(?P<username>\S*)\s*(?P<socket>\S*)\s*.*\), start (?P<datestr>.*?:.{2}).?\s?(?P<count>\d)?.*")
    # server_pattern=re.compile(r".*license server (..)\s.*")

    for key, ll_value in poll_list.items():
        try:
            log.debug("Checking Licence Server at '" + key + "'...")
            shell_command_string=poll_methods[ll_value["server_poll_method"]]["shell_command"] % ll_value
            log.debug(shell_command_string)

            # Clear from last loop
            for feature_ll_value in ll_value["tokens"]:
                feature_ll_value["real_usage_all"]=0
                feature_ll_value["real_usage_nesi"]=0
                feature_ll_value["users_nesi"]={}
            try:
                sub_return=subprocess.check_output(shell_command_string, shell=True)    #Removed .decode("utf-8") as threw error.     
                log.debug(key + " OK")
                features=poll_methods[ll_value["server_poll_method"]]["licence_pattern"].finditer(sub_return)
                # Create object from output.
                
                last_lic={}
                
                for licence in features:
                    untracked_warning="" # Message about untracked features.
                    group_dic=licence.groupdict()

                    # Continue if partial match
                    if group_dic["user"] == None:
                        last_lic=group_dic
                        continue

                    # Squash feature header
                    if group_dic["feature"] == None:
                        if "feature" in last_lic and last_lic["feature"]!=None:
                            group_dic["feature"]=last_lic["feature"]
                        else:
                            last_lic=group_dic
                            continue

                    if "count" not in group_dic or group_dic["count"] == None:
                        group_dic["count"] = 1

                    match_cluster=cluster_pattern.match(group_dic["host"])

                    # If not on nesi, set host to 'remote'
                    if match_cluster is None:
                        group_dic["host"]="remote"
                    else:
                        group_dic["host"]=match_cluster.group(0)

                    tracked_on_nesi=False
                    for token in ll_value["tokens"]:
                        # If tracked feature. Count
                        if group_dic["feature"].lower().strip() == token["licence_feature_name"].lower():
                            token["real_usage_all"]+=int(group_dic["count"])
                            tracked_on_nesi=True
                            if group_dic["host"]!="remote":
                                
                                token["real_usage_nesi"]+=int(group_dic["count"])

                                if group_dic["user"] not in token["users_nesi"]:
                                    token["users_nesi"][group_dic["user"]]={"count":0, "sockets":[]}

                                token["users_nesi"][group_dic["user"]]["count"]+=int(group_dic["count"])
                                token["users_nesi"][group_dic["user"]]["sockets"].append(group_dic["host"]) 

                        token["server_status"]="OK"    
                                            
                    if group_dic["host"].strip()!="remote" and (not tracked_on_nesi):
                        untracked_warning+= "\n" + group_dic["feature"] + " on '" + group_dic["host"] + "'"                
                
                    last_lic=group_dic
             
            except Exception as details:
                log.error("Failed to fetch " + key + " " + str(details))
                for token in ll_value["tokens"]:
                    token["server_status"]="FAIL"
                    ll_value["active"]=False
                    log.error("Fully soaking '" + ll_value["token_name"] + "'!!")   
            if untracked_warning:
                log.warning("In-use untracked features on '" + key + "':" + untracked_warning)
    
        except Exception as details:
            log.error("Failed " + key + " " + str(details))            

def do_maths():    
    
    log.info("Doing maths...")
    for value in licence_list.values():
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
            log.warning("Fully soaking " + value)
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

    def _update_res(cluster, soak):
        log.info("Attempting to update " + cluster + " reservation.")

        sub_input = "scontrol update -M " + cluster + " ReservationName=" + res_name + " " + soak
        ex_slurm_command(sub_input,"operator")

    def _create_res(cluster, soak):
        log.info("Attempting to update " + cluster + " reservation.")

        sub_input = "scontrol create -M " + cluster + " ReservationName=" + res_name + " StartTime=now Duration=infinite Users=root Flags=LICENSE_ONLY " + soak
        ex_slurm_command(sub_input)

    if os.environ.get("SOAK","").lower() == "false":
        log.info("Licence Soak skipped due to 'SOAK=FALSE'")
        return

    log.info("Applying soak...")
    res_name = "licence_soak"

    res_update_strings={}
    for ll_key, ll_value in licence_list.items():
        if not ll_value['enabled']:
            continue

        for cluster in ll_value["clusters"]:

            if cluster not in res_update_strings:

                res_update_strings[cluster] =  " licenses="
            
            res_update_strings[cluster] += ll_key + ":" + str(ll_value["token_soak"]) + ","    

    log.debug("Contructing reservation strings")
    log.debug(json.dumps(res_update_strings))

    for cluster, soak in res_update_strings.items():
        if cluster not in settings["clusters"].keys() or "enabled" not in settings["clusters"][cluster].keys() or not settings["clusters"][cluster]["enabled"]:
            log.warning("Skipping licence soak on " + cluster)
            continue
        if last_update[cluster]==soak:
            log.info("skipping soak. No change.")
            continue
        try:
            _update_res(cluster, soak)

        except Exception as details:
            log.error("Reservation update failed: " + str(details))
            log.info("Attempting to create new reservation.")
            try: 
                _create_res(cluster, soak)
            except Exception as details:
                log.error("Failed to create reservation: " + str(details))
            else:
                log.info("New reservation '" + res_name + "' created successfully.")
        else:
            log.info( cluster + " reservation updated successfully!")

def print_panel():
    hour_index = dt.datetime.now().hour - 1

    log.info("╔═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╦═════════════╗")
    log.info("║   Licence   ║    Server   ║    Status   ║    Total    ║ In Use All  ║ Average Use ║ In Use NeSI ║  Token Use  ║     Soak    ║")
    log.info("╠═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╬═════════════╣")
    
    for value in licence_list.values():
        if value["enabled"]:
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
        scontrol_string=ex_slurm_command(sub_input,"operator")
    except Exception as details:
        log.error("Failed to check scontrol licence usage. " + str(details))
    else:
        # Set current usage to zero
        for licence in licence_list.keys():
            licence_list[licence]["token_usage"]=0

        # Read by line
        scontrol_string_list=scontrol_string.split('\n')
        scontrol_string_list.pop(0) # First Line is bleh

        try:
            for line in scontrol_string_list:
                log.debug(line)
                if len(line)<6:
                    continue
                line_delimited=line.split('|')
                licences_per_user=line_delimited[6].split(',')
                # User may have multiple licences. Proccess for each.
                for licence_on_user in licences_per_user:
                    if not licence_on_user:
                        continue
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
        except Exception as e:
            print(e)

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

    def _fill(ll_key, ll_value):
        """Guess at any missing properties, these replace default ll_values"""

        if not ll_value["license_type"] and len(ll_key.split("@")[0].split('_'))>1:
            ll_value["license_type"] = ll_key.split("@")[0].split('_')[1]
            log.warning(ll_key + " license_type set to " + ll_value["license_type"])

        if not ll_value["software_name"]:
            ll_value["software_name"] = ll_key.split("@")[0].split('_')[0]        
            log.warning(ll_key + " software_name set to " + ll_value["software_name"])

        if not ll_value["licence_feature_name"] and len(ll_key.split("@")[0].split('_'))>1:
            ll_value["licence_feature_name"] = ll_key.split("@")[0].split('_')[1]
            log.warning(ll_key + " licence_feature_name set to " + ll_value["licence_feature_name"])

        if len(ll_key.split("@"))>1:
            if not ll_value["institution"]:
                ll_value["institution"] = ll_key.split("@")[1].split('_')[0]
                log.warning(ll_key + " institution set to " + ll_value["institution"])

            if not ll_value["faculty"] and len(ll_key.split("@")[1].split('_'))>1:
                ll_value["faculty"] = ll_key.split("@")[1].split('_')[1]
                log.warning(ll_key + " faculty set to " + ll_value["faculty"])

        if not ll_value["licence_file_group"] and ll_value["institution"]:
            ll_value["licence_file_group"] = ll_value["institution"]+"-org"
            log.warning(ll_key + " licence_file_group set to " + ll_value["licence_file_group"])
        
        if not ll_value["hourly_averages"] or not len(ll_value["hourly_averages"]) == 24:
            ll_value["hourly_averages"] = [0] * 24
            log.warning(ll_key + " file_group set.")

        if not ll_value["server_name"]:
            ll_value["server_name"]=ll_value["institution"]
            if ll_value["faculty"]:
                ll_value["server_name"] += "_" + ll_value["faculty"]
            log.warning(ll_key + " file_group set to " + ll_value["server_name"])

        if not ll_value["licence_name"]:
            ll_value["licence_name"]=ll_value["software_name"].lower()
            if ll_value["license_type"]:
                ll_value["licence_name"] += "_" + ll_value["license_type"]
            log.warning(ll_key + " file_group set to " + ll_value["licence_name"])

        if not ll_value["token_name"]:
            ll_value["token_name"]=ll_key
            log.warning(ll_key + " token_name set to " + ll_value["token_name"])

    def _address(ll_key, ll_value):
        """Validates path attached to licence"""

        filename_end = "_" + ll_value["faculty"] if ll_value["faculty"] else ""
        standard_address = "/opt/nesi/mahuika/" + ll_value["software_name"] + "/Licenses/" + ll_value["institution"] + filename_end + ".lic"   
        
        if ll_value["licence_file_path"]:                
            try:
                statdat = os.stat(ll_value["licence_file_path"])
                file_name = ll_value["licence_file_path"].split("/")[-1]

                owner = getpwuid(statdat.st_uid).pw_name
                group = getgrgid(statdat.st_gid).gr_name

                # Check permissions of file
                if statdat.st_mode == 432:
                    log.error(ll_key + " file address permissions look weird.")

                if ll_value["licence_file_group"] and group != ll_value["licence_file_group"]:
                    log.error(ll_value["licence_file_path"] + ' group is "' + group + '", should be "' + ll_value["licence_file_group"] + '".')

                if owner != settings["user"]:
                    log.error(ll_value["licence_file_path"] + " owner is '" + owner + "', should be '" + settings["user"] + "'.")
                        
                # if ll_value["licence_file_path"] != standard_address and ll_value["software_name"] and ll_value["institution"]:
                #     log.debug('Would be cool if "' + ll_value["licence_file_path"] + '" was "' + standard_address + '".')
                # Read lic file contents
                with open(ll_value["licence_file_path"]) as file:
                    sub_out = file.read()
                #raise Exception:
                #        log.error("Failed to check " + ll_key + " licence file contents at " + ll_value["licence_file_path"] + ": " + str(details))
                #else:
                
                match_address=poll_methods[ll_value["server_poll_method"]]["details_pattern"].match(sub_out).groupdict()
                ll_value["server_address"]=match_address["server_address"]
                ll_value["server_port"]=match_address["server_port"]
                if "server_host_id" in match_address:
                    ll_value["server_host_id"]=match_address["server_host_id"]
                
            except Exception as details:
                log.error("'" + ll_key + " has an invalid file path attached: " + str(details))
                ll_value["enabled"]=False
        else:
            ll_value["licence_file_path"]=standard_address
            log.warning(ll_key + " licence path set to " + standard_address)

    def _tokens(license_list):
        #Try get list of current slurm tokens
        # Try to fix a token if incorrect.
        def __update_token_count():
            log.info("Attempting to modify SLURM token " + key)

            if not ll_value["institution"]:         
                raise Exception("Token not created. Missing 'instituiton'.")               
            if not ll_value["real_total"]:         
                raise Exception("Token not created. Missing 'real_total'.")   
            if not ll_value["software_name"]:         
                raise Exception("Token not created. Missing 'software_name'")

            sub_input="sacctmgr -i modify resource Name=" + ll_value["licence_name"] + " Server=" + ll_value["server_name"] + " set Count=" + str(correct_count)
            ex_slurm_command(sub_input)

        def __update_token_share(cluster):

            log.info("Attempting to modify SLURM token " + key + " for " + cluster)

            if not (ll_value["institution"] and ll_value["real_total"] and ll_value["software_name"]):         
                raise Exception("Token not created. Missing one or more of 'instituiton', 'software_name', 'real_total'.")               
            
            sub_input="sacctmgr -i modify resource Name=" + ll_value["licence_name"] + " Server=" + ll_value["server_name"] +  " set percentallowed=" + str(correct_share) + " where cluster=" + cluster
            ex_slurm_command(sub_input)

        #Try to create  a token if missing.
        def __create_token(cluster):
            log.info("Attempting to create SLURM token " + key + " for " + cluster)

            if not (ll_value["institution"] and ll_value["real_total"] and ll_value["software_name"]):         
                raise Exception("Token not created. Missing one or more of 'instituiton', 'software_name', 'real_total'.")               

            sub_input="sacctmgr -i add resource Name=" + ll_value["licence_name"] + " Server=" + ll_value["server_name"] + " Count=" + str(correct_count) + " Type=License percentallowed=" + str(correct_share) +" where cluster=" + cluster

            ex_slurm_command(sub_input)

        try:
            sub_input="sacctmgr -pns show resource withcluster"
            log.debug(sub_input)
            string_data=ex_slurm_command(sub_input, "operator").strip()
        except Exception as details:
            log.error("Failed to check SLURM tokens. " + str(details))
        else:
            active_token_dict = {}

            #log.info("Tokens being divided between " + str(number_clusters) + " clusters.")

            # Format output data into dictionary 
            for lic_string in string_data.split("\n"):
                str_arr=lic_string.split("|")

                if str_arr[0] + "@" + str_arr[1] not in active_token_dict.keys():
                    active_token_dict[str_arr[0] + "@" + str_arr[1]]={'token_name':str_arr[0], 'server_name':str_arr[1],'count':int(str_arr[3]), 'share_total':int(str_arr[4]), 'clusters':{}}
                
                active_token_dict[str_arr[0] + "@" + str_arr[1]]['clusters'][str_arr[6]]=int(str_arr[7])
                log.debug(lic_string)

            #print(json.dumps(active_token_dict))

            for ll_key, ll_value in licence_list.items():

                # SLURM requires that each cluster is given a fraction of the full licence pool. 
                # In order to allow ALL clusters full access to the pool the total number of licence is set at <# clusters> * actual licence count.
                # However this means if multiple pulls of tokens are made across 2 clusters SLURM will be suprised when the licence tracker catches up with the token count.
                # TO IMPLIMENT
                # Temporary allocations need to be made to correspond to scheduled licence useage on other cluster.
                
                number_clusters=len(ll_value["clusters"])
                
                if number_clusters < 1 :
                    log.error(ll_key + " not active on any clusters?")
                    ll_value["enabled"]=False
                    log.info("Disabling licence " + ll_key + ".")
                    ll_value["server_status"]="NO_CLUSTER"
                    continue

                correct_share=int(100/number_clusters)
                correct_count=ll_value["real_total"] *  number_clusters
                log.info("Licence '" + ll_key + "' is in use on " + str(number_clusters) + " cluster(s) ( " + (", ".join(ll_value["clusters"])) + " ).")

                if ll_key not in active_token_dict.keys():
                    log.error(ll_key + " not in SACCT database. Attempting to add.")
                    try:
                        for cluster in ll_value["clusters"]:
                            __create_token(cluster)
                    except Exception as details:
                        log.error("Failed to add SLURM licence token: " + str(details))
                        ll_value["enabled"]=False
                        log.info("Disabling licence " + ll_key + ".")
                        ll_value["server_status"]="NULL_TOKEN"        
                        continue       
                    else:
                        log.info("SLURM token successfully added.")
                        restart()

                for cluster, share in active_token_dict[ll_key]["clusters"].items():
                    if correct_share != share:
                        log.error(ll_key + " has cluster share incorrectly set in SACCT database on " + cluster + " ( '" + str(share) +  "' should be '" + str(correct_share) + "'). Attempting to fix.")
                        if fix_slurm_share:
                            try:
                                __update_token_share(cluster)
                                # for cluster in ll_value["clusters"]:
                                #     if cluster not in settings["clusters"] or "enabled" not in settings["clusters"][cluster] or not settings["clusters"][cluster]["enabled"]:
                                #         continue
                                    
                            except Exception as details:
                                log.error("Failed to update SLURM token: " + str(details))
                                log.info("Disabling licence " + ll_key + ".")

                                ll_value["enabled"]=False
                                ll_value["server_status"]="SELFISH_TOKEN"
                                continue
                            else:
                                log.info("SLURM token successfully updated.")
                                restart()
                    

                if correct_count != active_token_dict[ll_key]["count"]:
                
                    log.error(ll_key + " has count incorrectly set in SACCT database. Attempting to fix.")
                    if fix_slurm_count:
                        try:
                            __update_token_count()
                        except Exception as details:
                            log.error("Failed to update SLURM token: " + str(details))
                            log.info("Disabling licence " + ll_key + ".")

                            ll_value["enabled"]=False
                            ll_value["server_status"]="WRONG_TOKEN"
                            continue
                        else:
                            log.info("SLURM token successfully updated.")
                            restart()

                
                if active_token_dict[ll_key]["count"]==0:
                    ll_value["enabled"]=False
                    ll_value["server_status"]="ZERO_TOKEN"

                    log.error(ll_key + " has 0 tokens in slurm db. Disabling.")
                    continue


                if active_token_dict[ll_key]["share_total"]<95:
                    log.warning('Slurm share only adds up to ' + str(active_token_dict[ll_key]["share_total"]) + '?? (This could be due to a cluster being disabled)')
                    # else:
                    #     If total on licence server does not match total slurm tokens, update slurm tokens.
                    #     if ll_value["real_total"] != int(active_token_dict[key][3])/2 and ll_value["real_total"]!=0:
                    #         log.error("SLURM TOKEN BAD, HAS " + str(int(active_token_dict[key][3])/2)  + " and should be " + str(ll_value["total"]))
                    #         if slurm_permissions=="operator" or slurm_permissions=="administrator":
                    #             try:
                    #                 sub_input="sacctmgr -i modify resource Name=" + ll_value["licence_name"].lower() + " Server=" + ll_value["server_name"].lower() + " set Count=" + str(int(ll_value["real_total"]*2))
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
                    #                 sub_input="sacctmgr -i modify resource Name=" + ll_value["licence_name"].lower() + " Server=" + ll_value["server_name"] + " percentallocated=100 where cluster=mahuika" +  " set PercentAllowed=50"
                    #                 log.debug(sub_input)
                    #                 subprocess.check_output(sub_input, shell=True)

                    #                 sub_input="sacctmgr -i modify resource Name=" + ll_value["licence_name"].lower() + " Server=" + ll_value["server_name"] + " percentallocated=100 where cluster=maui" +  " set PercentAllowed=50"
                    #                 log.debug(sub_input)
                    #                 subprocess.check_output(sub_input, shell=True)
                    #             except Exception as details:
                    #                 log.error(details)
                    #             else:
                    #                 log.info("Token modified successfully!")
                    #         else:
                    #             log.error("User does not have required SLURM permissions to fix SLURM tokens.")

    def _clusters(ll_key, ll_value, module_list):
        for module, module_value in module_list["modules"].items():
            if ll_value["software_name"].lower() == module.lower():
                    log.debug(ll_key +" exists as module")
                    log.debug(",".join(module_value["machines"]))
                    for cluster in module_value["machines"].keys():
                        if cluster not in ll_value["clusters"]:
                            ll_value["clusters"].append(cluster.lower())
                            log.info(cluster.lower() + " added to " + ll_key)
      
    log.info("Validating licence dictionary...")

    # Adds if licence exists in meta but not list
    for licence in licence_meta.keys():
        if not licence in licence_list:
            log.warning(licence + " is new licence. Being added to database wih default ll_values.")
            licence_list[licence] = {}
        
    for ll_key, ll_value in licence_list.items():
        # Unless specified 'active' and 'enabled' should always start as true.
        ll_value["active"]=True
        ll_value["enabled"]=True
        # Add missing values   
        for key in settings["default"].keys():
            if key not in ll_value:
                ll_value[key] = settings["default"][key]
        # Remove extra values  
        for key in ll_value.keys():
            if key not in settings["default"]:
                log.warning("Removed defunct key '" + key + "' from something" )
                ll_value.pop(key)

        _clusters(ll_key, ll_value, module_list)
        _fill(ll_key, ll_value)
        _address(ll_key, ll_value)

        # if not ll_value["licence_file_path"]:
        #     log.error(key + " must have licence file path or address and port specified in order to check with LMUTIL SHOULDNT SEE THIS")
        #     continue            
        # if not ll_value["licence_feature_name"]: 
        #     log.error(key + " must have feature specified in order to check with LMUTIL SHOULDNT SEE THIS")
        #     continue
        # if not ll_value["server_poll_method"] in poll_methods.keys(): 
        #     log.error(key + " must have poll method specified in order to check with LMUTIL SHOULDNT SEE THIS")
        #     continue
        # if not ll_value["server_address"]: 
        #     log.error(key + " must have address specified in order to check with LMUTIL SHOULDNT SEE THIS")
        #     continue


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
    get_nesi_use()
    
    do_maths()
     
    apply_soak()

    print_panel()
    c.writemake_json(settings["path_store"], licence_list)

    
settings = c.readmake_json("settings.json")
module_list = c.readmake_json(settings["path_modulelist"])

log.info("Starting...")
slurm_permissions=get_slurm_permssions()

# An error will be thrown if reservation is updated without change.
last_update={}
for cluster in settings["clusters"].keys():
    last_update[cluster]=""

#Settings need to be fixed
fix_slurm_share=True
fix_slurm_count=True

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
        print(sys.exc_info())
        log.error("Main loop failed: " + str(details))

    log.info("main loop time = " + str(time.time() - looptime))
    time.sleep(max(settings["poll_period"] - (time.time() - looptime), 0))

    # for key, ll_value in licence_list.items():
    # hour_index = dt.datetime.now().hour - 1
    # ll_value["in_use_real"] = int(feature["in_use_real"])

    # if ll_value["total"] != int(feature["total"]):
    #     log.warning("LMUTIL shows different total number of licences than recorded. Changing from '" + str(ll_value["total"]) + "' to '" + feature["total"] + "'")
    #     ll_value["total"] = int(feature["total"])

    # # Record to running history
    # ll_value["history"].append(ll_value["in_use_real"])

    # # Pop extra array entries
    # while len(ll_value["history"]) > ll_value["history_points"]:
    #     ll_value["history"].pop(0)

    # # Find modified in use ll_value
    # interesting = max(ll_value["history"])-ll_value["in_use_nesi"]
    # ll_value["soak"] = round(min(
    #     max(interesting + ll_value["buffer_constant"], interesting * (1 + ll_value["buffer_factor"]),0), ll_value["total"]
    # ))

    # # Update average
    # ll_value["day_ave"][hour_index] = (
    #     round(
    #         ((ll_value["in_use_real"] * settings["point_weight"]) + (ll_value["day_ave"][hour_index] * (1 - settings["point_weight"]))),
    #         2,
    #     )
    #     if ll_value["day_ave"][hour_index]
    #     else ll_value["in_use_real"]
    # )