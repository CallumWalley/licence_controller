#!python

import datetime
import json
import os
import re
import sched
import subprocess
import time
from grp import getgrgid
from pwd import getpwuid

from prometheus_client import Gauge, start_http_server

from clog import log

# encoding: utf-8
# === TO DO === #
# Add back module checks
# Promethius properly

# CHECKUSER = FALSE # Disables user checks.
# VALIDATE = FALSE # Disables validation check.
# SOAK = FALSE # Disables soak.
# LOGLEVEL = NONE, ERROR, WARNING, INFO, DEBUG

# cmd_method=<command line argument to get output>
# licence_pattern=<pattern applied to extract indiviudal licence users>
# server_pattern=<pattern applied to get global server properties>

# 'slurm_active' = Whether slurm db is to be contacted.
# 'polling_server' = Whether remote server should be contacted.
# 'visible_on_docs' = Whether licence should appear in documentation.
# 'slurm_blocked' = will set soak to 100%, preventing all programs running.

# Identifies whether NeSI host.
cluster_pattern = re.compile(r".*mahuika.*|.*maui.*|.*lander.*|.*nesi.*|wbn\d{3}|wcl\d{3}|vgpuwbg\d{3}|wbl\d{3}|wbh\d{3}|nid00\d{3}|wsn\d{3}|vgpuwsg\d{3}", flags=re.I)
poll_methods = {
    "ansysli_util": {
        "shell_command": "export ANSYSLMD_LICENSE_FILE=$(head -n 1 %(path)s | sed -n -e 's/.*=//p');linx64/ansysli_util -liusage",
        "licence_pattern": re.compile(
            r"(?P<user>[A-Za-z0-9]*)@(?P<host>\S*)\s*(?P<date>[\d\/]*?) (?P<time>[\d\:]*)\s*(?P<feature>[\S^\d]*)[^\d]*(?P<count>\d*)\s*(?P<misc>\S*)", flags=re.M
        ),
        "feature_pattern": "",
        "server_pattern": "",
        "details_pattern": re.compile(r"SERVER=(?P<server_port>\d*)@(?P<server_address>\S*)"),
    },
    "lmutil": {
        "shell_command": "linx64/lmutil lmstat -a -c %(path)s",
        "licence_pattern": re.compile(
            r"^(Users of )*(?P<feature>\S+):  \(Total of (?P<total>\d+).*|\n*^\s*(?P<user>\S*)\s*(?P<host>\S*).*\s(?P<date>\d+\/\d+)\s(?P<time>[\d\:]+).*$", flags=re.M
        ),
        "feature_pattern": "",
        "server_pattern": re.compile(r"^.* license server (?P<last_stat>.*) v(?P<version>.*)$", flags=re.M),
        "details_pattern": re.compile(r"SERVER\s+(?P<server_address>\S*)\s+(?P<server_>\d*|ANY)\s(?P<server_port>[\d|,]*)"),
    },
    "null": {"shell_command": "", "licence_pattern": "", "server_pattern": ""},
}
untracked = {}


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


def ex_slurm_command(sub_input, level="administrator"):
    log.debug("Attempting to run SLURM command '" + sub_input + "'.")
    if (level == "administrator" and slurm_permissions == "administrator") or (level == "operator" and (slurm_permissions == "operator" or slurm_permissions == "administrator")):
        try:
            output = subprocess.check_output(sub_input, shell=True).decode("utf-8")
        except Exception as details:
            raise Exception("Failed to execute SLURM command '" + sub_input + "':" + str(details))
        else:
            log.debug("Success!")
            time.sleep(5)  # Avoid spamming database
            return output
    else:

        with open("run_as_admin.sh", "a+") as f:
            f.write(sub_input + "\n")
        log.error("Writing command to 'run_as_admin.sh'")

        raise Exception("User does not have appropriate SLURM permissions to run this command.")


def validate():

    """Checks for inconinosistancies"""
    if os.environ.get("VALIDATE", "").lower() == "false":
        log.info("Skipping validation")
        return

    for server in server_list:
        try:
            for key, value in settings["default_server"].items():
                if key not in server:
                    log.info(str(server) + " missing property '" + key + "'. Setting to default.")
                    server[key] = value

            for feature, feature_values in server["tracked_features"].items():
                for key, value in settings["default_feature"].items():
                    if key not in feature_values:
                        log.info(feature + " missing property '" + key + "'. Setting to default.")
                        feature_values[key] = value
                # Notify if no cluster set
                if feature_values["slurm_active"] and feature_values["token_name"] and len(feature_values["clusters"]) < 1:
                    log.warning(feature_values["token_name"] + " is slurm_active, but is not assigned any cluster")

            statdat = os.stat(server["licence_file"]["path"])
            file_name = server["licence_file"]["path"].split("/")[-1]

            owner = getpwuid(statdat.st_uid).pw_name
            group = getgrgid(statdat.st_gid).gr_name

            # Check permissions of file
            if statdat.st_mode == 432:
                raise Exception(server["licence_file"]["path"] + " file address permissions look weird.")

            if server["licence_file"]["group"] and group != server["licence_file"]["group"]:
                log.warning(server["licence_file"]["path"] + ' group is "' + group + '", should be "' + server["licence_file"]["group"] + '".')

            if owner != settings["user"]:
                log.warning(server["licence_file"]["path"] + " owner is '" + owner + "', should be '" + settings["user"] + "'.")

            # if ll_value["licence_file_path"] != standard_address and ll_value["software_name"] and ll_value["institution"]:
            #     log.debug('Would be cool if "' + ll_value["licence_file_path"] + '" was "' + standard_address + '".')
            # Read lic file contents
            with open(server["licence_file"]["path"]) as file:
                sub_out = file.read()
                match_address = poll_methods[server["server"]["poll_method"]]["details_pattern"].match(sub_out).groupdict()
                if not server["server"]["address"]:
                    server["server"]["address"] = match_address["server_address"]
                elif server["server"]["address"] != match_address["server_address"]:
                    log.warning(file_name + " address mismatch: " + server["server"]["address"] + " -> " + match_address["server_address"])
                if not server["server"]["port"]:
                    server["server"]["port"] = match_address["server_port"]
                elif server["server"]["port"] != match_address["server_port"]:
                    log.warning(file_name + " port mismatch: " + server["server"]["port"] + " -> " + match_address["server_port"])
        except Exception as details:
            log.error("'" + server["licence_file"]["path"] + " has an invalid file path attached: " + str(details))
            server["server"]["polling_server"] = False
            server["server"]["status"] = "INVALID"

    writemake_json(settings["path_store"], server_list)


def get_slurm_permssions():
    try:
        shell_string = "sacctmgr show user ${USER} -Pn"
        log.debug(shell_string)
        lmutil_return = subprocess.check_output(shell_string, shell=True).decode("utf-8").strip().split("|")[-1].lower()  # Removed .decode("utf-8") as threw error.
    except Exception as details:
        log.error("Failed to fetch user permissions, assuming none: " + str(details))
    else:
        log.info("User SLURM permissions are '" + lmutil_return + "'")

        return lmutil_return


def get_nesi_use():
    log.info("Checking NeSI tokens... (period " + str(settings["squeue_poll_period"]) + "s)")

    # Build a string of all licences to check.
    all_licence_strings = {}

    for server in server_list:
        if "tracked_features" not in server:
            continue  # Skip if no features
        for feature in server["tracked_features"].values():
            if not feature["token_name"]:
                continue
            if not feature["slurm_active"]:
                continue
            for cluster in feature["clusters"]:
                if cluster not in settings["clusters"].keys():
                    log.error("No such cluster " + cluster)
                    continue
                if cluster not in all_licence_strings:
                    all_licence_strings[cluster] = ""
                all_licence_strings[cluster] += feature["token_name"] + ","
    log.debug(json.dumps(all_licence_strings))
    # Return if nothing to check.
    if not all_licence_strings:
        return

    # "clusters":{
    #     "mahuika":{
    #         "slurm_active":true
    #     },
    #     "maui":{

    #     },
    #     "maui_ancil":{}
    # }
    # For each cluster
    for cluster, status in settings["clusters"].items():

        if "slurm_active" not in status or not status["slurm_active"]:
            log.info("Skipping cluster " + cluster + " disabled or missing details.")
            continue
        # Search squeue for running or pending jobs
        sub_input = "squeue -h -M " + cluster + ' --format="%u|%C|%t|%r|%S|%N|%W" -L ' + all_licence_strings[cluster]

        # licence_pattern=re.compile(r"\s*(?P<username>\S*)\s*(?P<socket>\S*)\s*.*\), start (?P<datestr>.*?:.{2}).?\s?(?P<count>\d)?.*")
        log.debug(sub_input)
        try:
            scontrol_string = ex_slurm_command(sub_input, "operator")
        except Exception as details:
            log.error("Failed to check scontrol licence usage. " + str(details))
        else:
            # Set current usage to zero
            for server in server_list:
                if "tracked_features" not in server:
                    continue
                for feature in server["tracked_features"].values():
                    if "token_usage" not in feature:
                        continue
                    feature["token_usage"] = 0

            # Read by line
            scontrol_string_list = scontrol_string.split("\n")
            scontrol_string_list.pop(0)  # First Line is bleh

            # try:
            for line in scontrol_string_list:
                log.debug(line)
                if len(line) < 6:
                    continue
                line_delimited = line.split("|")
                username = line_delimited[0]
                licences_per_user = line_delimited[6].split(",")
                # User may have multiple licences. Proccess for each.
                for licence_token in licences_per_user:
                    if not licence_token:
                        continue

                    licence_token_name = licence_token.split(":")[0]
                    licence_token_count = licence_token.split(":")[1] if len(licence_token.split(":")) > 1 else 1

                    found = False
                    for server in server_list:
                        # Added flag because cant break out of two loops
                        for feature_name, feature_values in server["tracked_features"].items():
                            if feature_values["token_name"] == licence_token_name:

                                feature_values["token_usage"] += int(licence_token_count)
                                if username not in feature_values["users_nesi"]:
                                    feature_values["users_nesi"][username] = {"count": 0, "tokens": 0, "sockets": [], "soak": 0}

                                feature_values["users_nesi"][username]["tokens"] += int(licence_token_count)
                                feature_values["users_nesi"][username]["soak"] -= int(licence_token_count)
                                found = True
                            if found:
                                break
                        if found:
                            break
                    else:
                        log.error("Licence " + licence_token_name + " does not exist in licence controller.")
                        log.info("Empty licence " + licence_token_name + " added to meta.")
        schedul.enter(max(settings["squeue_poll_period"], 5), 1, get_nesi_use)


def poll_remote(server):
    # Skip if disabled or non existant.
    if "server" not in server or "polling_server" not in server["server"]:
        log.warning("Skipping " + server["server"]["address"] + " as invalid details.")
        server["server"] = settings["default"]["server"]
        server["server"]["status"] = "INVALID"
        return
    if not server["server"]["polling_server"]:
        log.info("Skipping server " + server["server"]["address"] + " as disabled.")
        server["server"]["status"] = "DISABLED"
        return
    try:
        server["server"]["status"] = "UNKNOWN"
        log.info("Checking Licence Server at '" + server["server"]["address"] + "'... (period " + str(server["server"]["poll_period"]) + "s)")
        shell_command_string = poll_methods[server["server"]["poll_method"]]["shell_command"] % server["licence_file"]
        log.debug(shell_command_string)

        sub_return = subprocess.check_output(shell_command_string, shell=True).strip().decode("utf-8", "replace")  # Removed .decode("utf-8") as threw error.
        log.debug(sub_return)
        # Match server details
        server_re_match = poll_methods[server["server"]["poll_method"]]["server_pattern"].search(sub_return)
        if server_re_match is None:
            return

        server_re_match_group = server_re_match.groupdict()
        log.debug(json.dumps(server_re_match_group))

        server["server"]["status"] = server_re_match_group["last_stat"]
        server["server"]["version"] = server_re_match_group["version"]
        log.info("'" + server["server"]["address"] + "' " + server_re_match_group["last_stat"])

        # server["server"]["last_time"]=server_re_match_group["last_time"]

        featureanduser_re_match = poll_methods[server["server"]["poll_method"]]["licence_pattern"].finditer(sub_return)
        if len(server["tracked_features"].keys()) < 1:
            log.warning("No features are being tracked on " + server["server"]["address"])
        # Clear previous totals
        for tracked_feature in server["tracked_features"].values():
            tracked_feature["usage_all"] = 0
            tracked_feature["usage_nesi"] = 0
            tracked_feature["users_nesi"] = {}

        last_lic = None

        # Read regex by line.
        for featureorline in featureanduser_re_match:
            group_dic = featureorline.groupdict()

            # If this is the case, it is a feature header.
            if group_dic["feature"] is not None:
                last_lic = group_dic
                tracked = False
                if group_dic["feature"] in server["tracked_features"].keys():
                    log.debug(group_dic["feature"] + " is tracked feature")
                    # Last_lic points to the licecne objects.
                    tracked = True
                    last_lic = server["tracked_features"][group_dic["feature"]]

                    if last_lic["total"] != int(group_dic["total"]):
                        log.warning("total was " + str(last_lic["total"]) + " at last count, now " + str(group_dic["total"]))
                        last_lic["total"] = int(group_dic["total"])

                elif group_dic["feature"] in server["untracked_features"]:
                    last_lic = group_dic["feature"]
                    log.debug(group_dic["feature"] + " is untracked feature")
                    continue
                else:
                    server["untracked_features"].append(group_dic["feature"])
                    last_lic = group_dic["feature"]
                    log.info("'" + group_dic["feature"] + "' being added to untracked features.")

            elif last_lic is not None:
                continue  # If not feature header we dont care.

            # If this is the case, it is a user.
            if group_dic["user"] is not None:
                match_cluster = cluster_pattern.match(group_dic["host"])

                if tracked:
                    # Count gets added regardless of socket
                    if "count" in group_dic and group_dic["count"].isdigit():
                        lic_count = int(group_dic["count"])
                    else:
                        lic_count = 1

                    last_lic["usage_all"] += lic_count

                    # Count gets added regardless of socket
                    if match_cluster:
                        # If user not already. Add them.
                        if group_dic["user"] not in last_lic["users_nesi"]:
                            last_lic["users_nesi"][group_dic["user"]] = {"count": 0, "tokens": 0, "sockets": [], "soak": 0}

                        last_lic["usage_nesi"] += lic_count
                        last_lic["users_nesi"][group_dic["user"]]["count"] += lic_count
                        last_lic["users_nesi"][group_dic["user"]]["soak"] += lic_count
                        last_lic["users_nesi"][group_dic["user"]]["sockets"].append(match_cluster.group(0))
                else:
                    if match_cluster:
                        log.info("Untracked feature: " + last_lic + " being used by " + group_dic["user"] + " on " + group_dic["host"])

    except Exception as details:
        log.error("Failed to check '" + server["server"]["address"] + "': " + str(type(details)) + " " + str(details))
        server["server"]["status"] = "DOWN"
    else:
        writemake_json(settings["path_store"], server_list)
        schedul.enter(server["server"]["poll_period"], 1, poll_remote, argument=(server,))


def apply_soak():
    def _do_maths(feature):

        log.debug("Doing maths...")
        hour_index = datetime.datetime.now().hour - 1

        feature["history"].append(feature["usage_all"])
        while len(feature["history"]) > settings["history_points"]:
            feature["history"].pop(0)

        # Update average
        if feature["hourly_averages"][hour_index]:
            feature["hourly_averages"][hour_index] = round(
                ((feature["usage_all"] * settings["point_weight"]) + (feature["hourly_averages"][hour_index] * (1 - settings["point_weight"]))), 2
            )
        else:
            feature["hourly_averages"][hour_index] = feature["usage_all"]

        if not feature["slurm_active"]:
            feature["token_soak"] = "--"
            log.debug("Skipping  " + feature + " disabled")
        else:
            feature["token_soak"] = int(min(max(max(feature["history"]), feature["usage_all"]) + feature["buffer_constant"], feature["total"]))

    def _update_res(cluster, soak):
        log.info("Attempting to update " + cluster + " reservation.")

        sub_input = "scontrol update -M " + cluster + " ReservationName=" + res_name + " " + soak
        ex_slurm_command(sub_input, "operator")

    def _create_res(cluster, soak):
        log.info("Attempting to update " + cluster + " reservation.")

        sub_input = "scontrol create -M " + cluster + " ReservationName=" + res_name + " StartTime=now Duration=infinite Users=root Flags=LICENSE_ONLY " + soak
        ex_slurm_command(sub_input)

    if os.environ.get("SOAK", "").lower() == "false":
        log.info("Licence Soak skipped due to 'SOAK=FALSE'")
        return

    log.info("Applying soak...")
    res_name = "licence_soak"

    res_update_strings = {}
    for server in server_list:
        for tracked_feature_name, tracked_feature_value in server["tracked_features"].items():

            _do_maths(tracked_feature_value)

            if not tracked_feature_value["slurm_active"]:
                continue
            if not tracked_feature_value["token_name"]:
                continue

            for cluster in tracked_feature_value["clusters"]:
                if tracked_feature_value["token_soak"]:
                    if cluster not in res_update_strings:
                        res_update_strings[cluster] = " licenses="
                    res_update_strings[cluster] += tracked_feature_value["token_name"] + ":" + str(tracked_feature_value["token_soak"]) + ","

        log.debug("Contructing reservation strings")
        log.debug(json.dumps(res_update_strings))

    for cluster, soak in res_update_strings.items():
        if cluster not in settings["clusters"].keys() or "slurm_active" not in settings["clusters"][cluster].keys() or not settings["clusters"][cluster]["slurm_active"]:
            log.warning("Skipping licence soak on " + cluster)
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
            log.info(cluster + " reservation updated successfully!")

    schedul.enter(settings["squeue_poll_period"], 1, apply_soak)


# def promethisise():
# for monitor in monitors:
#         next(monitor)
def print_panel():
    def fit_2_col(inval, colsize=13):
        """Trims whatever value input to colsize and centres it"""
        trimmedstr = (str(inval)[: (colsize - 2)] + "..") if len(str(inval)) > (colsize - 2) else str(inval)
        censtr = trimmedstr.center(colsize)
        return censtr

    dashboard = ""

    hour_index = datetime.datetime.now().hour - 1

    dashboard += "O========================================v=========v=============v=============v=============v=============v=============v======================================================O\n"
    dashboard += "|          Server/Feature/User           |  Status | Average Use | In Use All  | In Use NeSI |  Token Use  |     Soak    |                        Sockets                       |\n"

    for server in server_list:
        if "tracked_features" not in server or "server" not in server or "polling_server" not in server["server"] or not server["server"]["polling_server"]:
            continue
        dashboard += "O========================================+=========+=============+=============+=============+=============+=============+======================================================O\n"
        dashboard += (
            "|"
            + fit_2_col(server["server"]["address"], 40)
            + "|"
            + fit_2_col(server["server"]["status"], 9)
            + "|"
            + "             |" * 5
            + "                                                      |\n"
        )

        for feature_key, feature_value in server["tracked_features"].items():
            try:
                if feature_value["buffer_constant"] > 1:
                    buffer_note = " (" + str(feature_value["buffer_constant"]) + ")"
                else:
                    buffer_note = ""
                dashboard += (
                    "|"
                    + " " * 19
                    + "L"
                    + fit_2_col(feature_key, 20)
                    + "|"
                    + fit_2_col(feature_value["total"], 9)
                    + "|"
                    + fit_2_col(feature_value["hourly_averages"][hour_index])
                    + "|"
                    + fit_2_col(feature_value["usage_all"])
                    + "|"
                    + fit_2_col(feature_value["usage_nesi"])
                    + "|"
                    + fit_2_col(feature_value["token_usage"])
                    + "|"
                    + fit_2_col(str(feature_value["token_soak"]) + buffer_note)
                    + "|                                                      |\n"
                )
                if feature_value["usage_nesi"]:
                    for user, usage in feature_value["users_nesi"].items():
                        dashboard += (
                            "|"
                            + " " * 29
                            + "L"
                            + fit_2_col(user, 10)
                            + "|         |             |             |"
                            + fit_2_col(usage["count"])
                            + "|"
                            + fit_2_col(usage["tokens"])
                            + "|"
                            + fit_2_col(usage["soak"])
                            + "|"
                            + fit_2_col(",".join(usage["sockets"]), 54)
                            + "|\n"
                        )
            except Exception as details:
                log.error("Wonky line in dashboard " + str(type(details)) + " " + str(details))

    dashboard += "O========================================^=========^=============^=============^=============^=============^=============^======================================================O\n"
    # main_dashboard.refresh()
    # main_dashboard.addstr(1,0,dashboard)
    print(dashboard)
    schedul.enter(settings["redraw_dash_period"], 1, print_panel)


settings = readmake_json("settings.json")
module_list = readmake_json(settings["path_modulelist"])

# Is correct user
if os.environ["USER"] != settings["user"] and not os.environ.get("CHECKUSER", "").lower() == "false":
    log.error("Command should be run as '" + settings["user"] + "' as it owns licence files. ('export CHECKUSER=FALSE' to disable this check)")
    exit()

# Clear
open("run_as_admin.sh", "w").close()

log.info("Starting...")
slurm_permissions = get_slurm_permssions()

# An error will be thrown if reservation is updated without change.


# Settings need to be fixed
log.debug(json.dumps(settings))


server_list = readmake_json(settings["path_store"])


# Start prom server
try:
    start_http_server(settings["prom_port"])
except Exception as details:
    log.warning("Couldn't start Promethius server: " + str(details))
else:
    for server in server_list:
        if "tracked_features" not in server:
            continue
        for tracked_feature_key, tracked_feature_values in server["tracked_features"].items():
            if "prometheus_gauge" not in tracked_feature_values:
                continue
            tracked_feature_values["prometheus_gauge"] = Gauge(
                tracked_feature_key + "_license_tokens_used", tracked_feature_values["name"] + " license tokens in use according to the license server"
            )

# Promethius Monitors
monitors = []

# Check licence validity
validate()

# Create Sceduler
schedul = sched.scheduler(time.time, time.sleep)


for server in server_list:
    poll_remote(server)
get_nesi_use()
apply_soak()
print_panel()

# Will run as long as items scehudelddeld
schedul.run()
