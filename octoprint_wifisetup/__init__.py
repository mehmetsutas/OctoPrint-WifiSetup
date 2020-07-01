# coding=utf-8
from __future__ import absolute_import
import subprocess
import os
import time
from threading import Thread
import fileinput
import re

__author__ = "Gina Häußge <osd@foosel.net>"
__license__ = 'GNU Affero General Public License http://www.gnu.org/licenses/agpl.html'
__copyright__ = "Copyright (C) 2014 The OctoPrint Project - Released under terms of the AGPLv3 License"


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
                                octoprint.plugin.AssetPlugin):

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
        hostname = self._settings.get(["hostname"])
        if hostname:
            return hostname
        else:
            import socket
            return socket.gethostname() + ".local"

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
            dict(type="settings", name="WIFI"),
            dict(type="tab", name="WIFI")
        ]

    ##~~ SimpleApiPlugin API

    def get_api_commands(self):
        return dict(
            refresh_wifi=[],
            configure_wifi=[],
            forget_wifi=[]
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
            wificheck=wificheck
        ))

    def on_api_command(self, command, data):
        # any commands processed after this check require admin permissions
#        if not admin_permission.can():
#            return make_response("Insufficient rights", 403)

        if not Permissions.PLUGIN_WIFISETUP_ACCESS.can():
            return None

        if command == "refresh_wifi":
            return jsonify(self._get_wifi_list(force=True))

        if command == "configure_wifi":
            if data["psk"]:
                self._logger.info("Configuring wifi {ssid} and psk...".format(**data))
            else:
                self._logger.info("Configuring wifi {ssid}...".format(**data))

            self._configure_and_select_wifi(data["ssid"], data["psk"], force=data["force"] if "force" in data else False)

        elif command == "forget_wifi":
            self._forget_wifi()

            

    ##~~ AssetPlugin API

    def get_assets(self):
        return dict(
            js=["js/wifisetup.js"],
            css=["css/wifisetup.css"],
            less=["less/wifisetup.less"]
        )

    ##~~ Private helpers

    def _get_wifi_list(self, force=False):
#        if not Permissions.PLUGIN_OCTOPRINT_WIFISETUP_ACCESS.can():
#            return None
        iwlist_raw = subprocess.Popen(['sudo', '/sbin/iwlist', 'scan'], stdout=subprocess.PIPE)
        ap_list, err = iwlist_raw.communicate()
        retcode = iwlist_raw.poll()
        if retcode:
            self._logger.info("Error while listing wifi: retcode = " + retcode)

        result = []

        for line in ap_list.decode('utf-8').rsplit('\n'):
            if 'Address' in line:
                ap_address = line[29:]
            if 'level' in line:
                ap_quality = line[48:51]
            if 'Encryption' in line:
                ap_encryption = line[35:]
            if 'ESSID' in line:
                ap_ssid = line[27:-1]
                result.append(dict(ssid=ap_ssid, address=ap_address, quality=ap_quality, encrypted=ap_encryption))

        return result
        
    def _check_wifi(self, force=False):
        checkwifi_raw = subprocess.Popen(['sudo', '/sbin/ifconfig'], stdout=subprocess.PIPE)
        wifi_list, err = checkwifi_raw.communicate()
        retcode = checkwifi_raw.poll()
        if retcode:
            self._logger.info("Error while checking wifi: retcode = " + retcode)

        for line in wifi_list.decode('utf-8').rsplit('\n'):
            if 'wlan0:' in line:
                return True
        return False
        

    def _get_status(self):
        mac_addr_pattern = r"[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}"
        iwconfig_re = re.compile('ESSID:"(?P<ssid>[^"]+)".*Access Point: (?P<address>%s).*' % mac_addr_pattern , re.DOTALL)

        iwconfig_run = subprocess.Popen(['sudo', '/sbin/iwconfig', 'wlan0'], stdout=subprocess.PIPE)
        iwconfig_output, err = iwconfig_run.communicate()
        retcode = iwconfig_run.poll()
        if retcode:
            self._logger.info("Error while checking status: retcode = " + retcode)
            return dict(ssid=None, address=None)

        m = iwconfig_re.search(iwconfig_output)
        if not m:
            return dict(ssid=None, address=None)

        return dict(ssid=m.group('ssid'), address=m.group('address'))

    def _configure_and_select_wifi(self, ssid, psk, force=False):
    
        temp_conf_file = open('/tmp/wpa_supplicant.conf.tmp', 'w')

        temp_conf_file.write('ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n')
        temp_conf_file.write('update_config=1\n')
        temp_conf_file.write('p2p_disabled=1\n')
        temp_conf_file.write('\n')
        temp_conf_file.write('network={\n')
        temp_conf_file.write('    ssid="' + ssid + '"\n')

        if psk == '':
            temp_conf_file.write('    key_mgmt=NONE\n')
        else:
            temp_conf_file.write('    psk="' + psk + '"\n')

        temp_conf_file.write('    }\n')
        temp_conf_file.write('country=TR\n')

        temp_conf_file.close

        os.system('sudo mv /tmp/wpa_supplicant.conf.tmp /etc/wpa_supplicant/wpa_supplicant.conf')
        time.sleep(2)
        wpacli_run = subprocess.Popen(['/sbin/wpa_cli', '-i', 'wlan0', 'reconfigure'], stdout=subprocess.PIPE) #os.system('wpa_cli -i wlan0 reconfigure')

    
    def _forget_wifi(self):
        temp_conf_file = open('/tmp/wpa_supplicant.conf.tmp', 'w')

        temp_conf_file.write('ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n')
        temp_conf_file.write('update_config=1\n')
        temp_conf_file.write('p2p_disabled=1\n')
        temp_conf_file.write('\n')
        temp_conf_file.write('country=TR\n')

        temp_conf_file.close

        os.system('sudo mv /tmp/wpa_supplicant.conf.tmp /etc/wpa_supplicant/wpa_supplicant.conf')
        time.sleep(2)
        
        wpacli_run = subprocess.Popen(['/sbin/wpa_cli', '-i', 'wlan0', 'reconfigure'], stdout=subprocess.PIPE)
        
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
__plugin_pythoncompat__ = ">=2.7,<3"
__plugin_description__ = "Setup wifi credentials"
__plugin_disabling_discouraged__ = gettext("Without this plugin you will no longer be able to setup "
                                           "wifi credentials through Octoprint UI.")
__plugin_license__ = "AGPLv3"

__plugin_implementation__ = WifisetupSettingsPlugin()
__plugin_hooks__ = {
                        "octoprint.access.permissions": __plugin_implementation__.get_additional_permissions
                        }
def __plugin_check__():
    import sys
    if sys.platform == 'linux2':
        return True

    logging.getLogger("octoprint.plugins." + __name__).warn("The wifisetup plugin only supports Linux")
    return False
