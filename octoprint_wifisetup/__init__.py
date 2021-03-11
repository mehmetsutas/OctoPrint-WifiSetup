# coding=utf-8
from __future__ import absolute_import
import subprocess
import os
import time
import threading
import socket
#from threading import Thread
from builtins import dict
#import fileinput
import re

__author__ = "Mehmet Sutas <msutas@gmail.com>"
__license__ = 'GNU Affero General Public License http://www.gnu.org/licenses/agpl.html'
__copyright__ = "Copyright (C) 2021 Mehmet Sutas - Released under terms of the AGPLv3 License"


import logging
from flask import jsonify, make_response
import flask
from flask_babel import gettext

import octoprint.plugin

from octoprint.server import admin_permission
from octoprint.server import user_permission
from octoprint.access import ADMIN_GROUP, USER_GROUP
from octoprint.access.permissions import Permissions

class WifisetupSettingsPlugin(octoprint.plugin.SettingsPlugin,
                              octoprint.plugin.TemplatePlugin,
                              octoprint.plugin.SimpleApiPlugin,
                              octoprint.plugin.AssetPlugin,
                              octoprint.plugin.StartupPlugin):

    def __init__(self):
        self.address = None

    # Additional permissions hook

    def get_additional_permissions(self):
        return [
            dict(key="ACCESS",
                 name="WIFI Setup Access",
                 description=gettext("Allows access to WIFI setup"),
                 roles=["access"],
                 default_groups=[USER_GROUP, ADMIN_GROUP])
        ]

    @property
    def hostname(self):
#        server_ip = [(s.connect((self._settings.global_get(["server","onlineCheck","host"]), self._settings.global_get(["server","onlineCheck","port"]))), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
        hostname = self._settings.get(["hostname"])
        if hostname:
            return hostname
        else:
            import socket
            return socket.gethostname() + ".local"
        return server_ip

    ##~~ StartupPlugin
    
    def on_after_startup(self):

        t1 = threading.Timer(3,self._activate_ap)
        t1.start()
        self._logger.info("Startup Check")

        return

    ##~~ SettingsPlugin

    def on_settings_save(self, data):
        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
        self.address = self._settings.get(["socket"])

    def get_settings_defaults(self):
        return dict(
            hostname=None,
            timeout=10
        )

    ##~~ TemplatePlugin API

    def get_template_configs(self):
        return [
#            dict(type="settings", name="WIFI"),
            dict(type="tab", name="WIFI")
        ]

    ##~~ SimpleApiPlugin API

    def get_api_commands(self):
        return dict(
            list_wifi=[],
            configure_wifi=[],
            forget_wifi=[],
            radio_on=[],
            radio_off=[],
            ap_off=[]
        )

    def on_api_get(self, request):

#        if not Permissions.PLUGIN_OCTOPRINT_WIFISETUP_ACCESS.can():
#            return make_response("Insufficient rights", 403)
            
        status = self._get_status()
        wifis = self._get_wifi_list()
        wificheck = self._check_wifi()

        return jsonify(dict(
            wifis=wifis,
            status=status,
            hostname=self.hostname,
            wifiradio=wificheck
        ))

    def on_api_command(self, command, data):
        # any commands processed after this check require admin permissions
#        if not admin_permission.can():
#            return make_response("Insufficient rights", 403)

        status = self._get_status()
        wifis = self._get_wifi_list()
        wificheck = self._check_wifi()

        if not Permissions.PLUGIN_WIFISETUP_ACCESS.can():
            return None

        if command == "list_wifi":
#            return jsonify(self._get_wifi_list(force=True))
            return flask.make_response(jsonify(self._get_wifi_list(force=True)), 200)

        elif command == "configure_wifi":
            if data["psk"]:
                self._logger.info("Configuring wifi {ssid} and psk...".format(**data))
            else:
                self._logger.info("Configuring wifi {ssid}...".format(**data))

            self._configure_and_select_wifi(data["ssid"], data["psk"])

        elif command == "radio_on":
            self.radio_on()
            
        elif command == "radio_off":
            self.radio_off()
            
        elif command == "ap_off":
            self._deactivate_ap()

        elif command == "forget_wifi":
            self._forget_wifi()
        
        return flask.jsonify(dict(wifis=wifis,
                                          status=status,
                                          hostname=self.hostname,
                                          wifiradio=wificheck))

    ##~~ AssetPlugin API

    def get_assets(self):
        return dict(
            js=["js/wifisetup.js"],
            css=["css/wifisetup.css"],
            less=["less/wifisetup.less"]
        )

    # ~ action command handler

    def action_command_listwifi(self, comm, line, action, *args, **kwargs):

        parts = action.split(None)
        action = parts[0]

        if len(parts) == 1:
            action = parts[0]
        elif len(parts) == 2:
            action = parts[0]
            ssid = parts[1]
        else:
            action, ssid, pwd = parts

        if action != "listwifi" or action != "setwifi":
            return

        self._logger.info("Action Command: " + action)

        if action == "listwifi":
            t2 = threading.Thread(target=self._send_wifi_list)
        elif action == "setwifi":
            t2 = threading.Thread(target=self._configure_and_select_wifi, args=(ssid,pwd,))
            
        message = parameter.strip()
        self._notifications.append((time.time(), message))
        self._plugin_manager.send_plugin_message(self._identifier, {"message": message})

        self._logger.info("Got a notification: {}".format(message))

    def _send_wifi_list(self):
        
        self._logger.info("Begin list wifi to printer")
        result = []
        stat = self._get_status()
        
        result.append("Begin wifi list")

        if stat["wifi"]:
        
            iwlist_raw = subprocess.Popen(['sudo', '/usr/bin/nmcli', '-t', '-f', 'SSID,SIGNAL', 'dev', 'wifi', 'list'], stdout=subprocess.PIPE)
            ap_list, err = iwlist_raw.communicate()
            retcode = iwlist_raw.poll()

            if retcode:
                self._logger.warning("Error while listing wifi to printer: retcode = " + str(retcode))
                return

            for line in ap_list.decode('utf-8').rsplit('\n'):
        
                if len(line) > 0:
                    lsip = len.split(":")

                    ap_ssid,ap_quality = lsip

                    result.append(ap_ssid + " " + ap_quality)
                    
                    self._logger.info(ap_ssid + " " + ap_quality)

        result.append("End wifi list")
            
        self._printer.commands(result,force=True)
        
        self._logger.info("End list wifi to printer")

        return
        
    ##~~ Private helpers
    
    def _deactivate_ap(self):

        self._logger.info("Deactivate AP")
        dap_run = subprocess.run(['sudo', '/usr/bin/nmcli', 'connection', 'down', 'con-r3d'])

        return

    def _activate_ap(self):
    
        self._logger.info("Cleanup")

        subprocess.run(['find', '/home/octo/.octoprint/timelapse/tmp/', '-mtime', '14', '-type', 'f', '-not', '-name', '"*.yaml"', '-delete'])

        subprocess.run(['find', '/home/octo/.octoprint/logs/', '-mtime', '30', '-type', 'f', '-not', '-name', '"*.yaml"', '-delete'])

        subprocess.run(['ls', '/home/octo/.octoprint/uploads/', '-tp', '|', 'grep', '-v', '\'/$\'', '|', 'tail', '-n', '+6', '|', 'xargs', '-I', '{}', 'rm', '--', '/home/octo/.octoprint/uploads/{}'])

        subprocess.run(['ls', '/home/octo/.octoprint/timelapse/', '-tp', '|', 'grep', '-v', '\'/$\'', '|', 'tail', '-n', '+6', '|', 'xargs', '-I', '{}', 'rm', '--', '/home/octo/.octoprint/timelapse/{}'])

#        stat1 = self._get_status()

#        if ((self._check_wifi()) and (stat1["ssid"] is None)):
#            sup_run = subprocess.run(['sudo', '/usr/bin/nmcli', 'connection', 'up', 'con-r3d'])
#            self._logger.info("Activate AP Run")

        return

    def _get_wifi_list(self, force=False):
#        if not Permissions.PLUGIN_OCTOPRINT_WIFISETUP_ACCESS.can():
#            return None

        result = []
        stat = self._get_status()

        if stat["wifi"]:
        
            iwlist_raw = subprocess.Popen(['sudo', '/usr/bin/nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,SECURITY,ACTIVE', 'dev', 'wifi', 'list'], stdout=subprocess.PIPE)
            ap_list, err = iwlist_raw.communicate()
            retcode = iwlist_raw.poll()

            if retcode:
                self._logger.warning("Error while listing wifi: retcode = " + str(retcode))
                return result

            for line in ap_list.decode('utf-8').rsplit('\n'):
        
                if len(line) > 0:
                    lrep = line.replace("\\:","-")
                    lsip = lrep.split(":")

                    ap_address = lsip[1].replace("-",":")
                    ap_quality = lsip[2]
                    ap_encryption = lsip[3]
                    ap_ssid = lsip[0]

                    result.append(dict(ssid=ap_ssid, address=ap_address, quality=ap_quality, encrypted=ap_encryption))

        return result
        
    def _check_wifi(self, force=False):
        checkwifi_raw = subprocess.Popen(['sudo', '/usr/bin/nmcli', '-t', 'radio', 'wifi'], stdout=subprocess.PIPE)
        wifi_list, err = checkwifi_raw.communicate()
        retcode = checkwifi_raw.poll()
        if retcode:
            self._logger.warning("Error while checking wifi radio: retcode = " + str(retcode))
            return False

        line = wifi_list.decode('utf-8').split('\n')

#        self._logger.info("Wifi radio status: " + line[0])

        if line[0] == "enabled":
            return True

        return False
        
    def _get_status(self):

        ap_ssid = None
        ap_ap = False
        ap_wifi = False
        ap_wired = False
        
        if self._check_wifi():
        
            nmstatus_run = subprocess.Popen(['sudo', '/usr/bin/nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show'], stdout=subprocess.PIPE)
            nmstatus_output, err = nmstatus_run.communicate()
            retcode = nmstatus_run.poll()
            
            if retcode:
                self._logger.warning("Error while checking connection status: retcode = " + str(retcode))
                return dict(ssid=ap_ssid, ap=ap_ap, wired=ap_wired, wifi=ap_wifi)

            for line in nmstatus_output.decode('utf-8').rsplit('\n'):

                if len(line) > 0:

                    lsip = line.split(":")

                    if lsip[1] == "eth0":
                        ap_wired = True
                    elif lsip[1] == "wlan0":
                        if lsip[0] == "con-r3d":
                            ap_ap = True
                        else:
                            ap_wifi = True
                            ap_ssid = lsip[0]
                            break
                    else:
                        ap_wifi = True
                        ap_ssid = None
                            
#        self._logger.info("Wifi status (SSID, AP, WIRED, WIFI): " + ap_ssid + ", " + ap_ap + ", " + ap_wired + ", " + ap_wifi)
        
        return dict(ssid = ap_ssid, ap = ap_ap, wired = ap_wired, wifi = ap_wifi)

    def _configure_and_select_wifi(self, ssid, psk):

        stat = self._get_status()

        if stat["ap"]:
        
            apdown_raw = subprocess.Popen(['sudo', '/usr/bin/nmcli', 'connection', 'down', 'con-r3d'], stdout=subprocess.PIPE)
            apdown_list, err = apdown_raw.communicate()
            retcode = apdown_raw.wait(timeout=3)

            if retcode:
                self._logger.warning("Error while shutting down ap: retcode = " + str(retcode))
                return

            self._logger.info("Configure Wifi AP Down")

        subprocess.run(['sudo', '/usr/bin/nmcli', 'connection', 'delete', ssid])
        subprocess.run(['sudo', '/usr/bin/nmcli', 'connection', 'add', 'type', 'wifi', 'ifname', 'wlan0',
                        'con-name', ssid, 'autoconnect', 'yes', 'ssid', ssid, 'wifi-sec.key-mgmt', 'wpa-psk',
                        '802-11-wireless-security.auth-alg', 'open', 'wifi-sec.psk', psk])
        subprocess.run(['sudo', '/usr/bin/nmcli', 'connection', 'up', ssid])
        
#        apdown_raw = subprocess.Popen(['sudo', '/usr/bin/nmcli', 'connection', 'delete', ssid], stdout=subprocess.PIPE)
#        ssdel_list, err = apdown_raw.communicate()
#        retcode = apdown_raw.wait(timeout=5)

#        if retcode:
#            self._logger.warning("Error while deleting SSID: " + ssid + " retcode = " + str(retcode) + ssdel_list.decode('utf-8'))
#        else:
#            self._logger.info("Configure Wifi Delete SSID: " + ssid)

#        apdown_raw = subprocess.Popen(['sudo', '/usr/bin/nmcli', 'device', 'wifi', 'connect', ssid, 'password', psk], stdout=subprocess.PIPE)
#        ssadd_list, err = apdown_raw.communicate()
#        retcode = apdown_raw.wait(timeout=5)

#        if retcode:
#            self._logger.warning("Error while adding SSID: " + ssid + " PSK: " + psk + " retcode = " + str(retcode) + ssadd_list.decode('utf-8'))
#        else:
#            self._logger.info("Configure Wifi Connect SSID: " + ssid + " PSK: " + psk)
                
        return
    
    def _forget_wifi(self):
        inmrun_run = subprocess.Popen(['sudo', '/usr/bin/nmcli', '-t', '-f', 'IN-USE,SSID', 'dev', 'wifi', 'list'], stdout=subprocess.PIPE)
        try:
            inmconfig_output, err = inmrun_run.communicate()
        except TimeoutExpired:
            proc.kill()
        retcode = inmrun_run.poll()
        
        if retcode:
            self._logger.warning("Error while checking status on forget: retcode = " + str(retcode))
            return None

        for line in inmconfig_output.decode('utf-8').rsplit('\n'):

            if len(line) > 0:
                lsip = line.split(":")

                if lsip[0] == "*":
                    ap_address = lsip[1]
                    subprocess.run(['sudo', '/usr/bin/nmcli', 'connection', 'delete', ap_address])
                    self._logger.info("Forget Wifi Delete SSID")
                    break
        
        return

    def radio_on(self):
        ron_run = subprocess.run(['sudo', '/usr/bin/nmcli', 'radio', 'wifi', 'on'])
        self._logger.info("Set Radio On")
        return

    def radio_off(self):
        roff_run = subprocess.run(['sudo', '/usr/bin/nmcli', 'radio', 'wifi', 'off'])
        self._logger.info("Set Radio Off")
        return

    def get_update_information(self):
        return dict(
            resource_monitor=dict(
                displayName="Wifi Setup",
                displayVersion=self._plugin_version,
                type="github_release",
                user="msutas",
                repo="OctoPrint-WifiSetup",
                current=self._plugin_version,
                pip="https://github.com/msutas/OctoPrint-WifiSetup/archive/{target_version}.zip"
            )
        )

__plugin_name__ = "WIFI SETUP"
__plugin_author__ = "Mehmet Sutas"
__plugin_pythoncompat__ = ">=2.7,<4"
__plugin_description__ = "Setup wifi credentials"
__plugin_disabling_discouraged__ = gettext("Without this plugin you will no longer be able to setup "
                                           "wifi credentials through Octoprint UI.")
__plugin_license__ = "AGPLv3"

__plugin_implementation__ = WifisetupSettingsPlugin()
__plugin_hooks__ = {
                        "octoprint.access.permissions": __plugin_implementation__.get_additional_permissions,
                        "octoprint.comm.protocol.action": __plugin_implementation__.action_command_listwifi,
                        }
def __plugin_check__():
    import sys
    if sys.platform.startswith('linux'):
        return True

    logging.getLogger("octoprint.plugins." + __name__).warn("The wifisetup plugin only supports Linux")
    return False
