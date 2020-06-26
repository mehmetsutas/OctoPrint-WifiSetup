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

import octoprint.plugin

from octoprint.server import admin_permission
from octoprint.access import ADMIN_GROUP, USER_GROUP
from octoprint.access.permissions import Permissions

class NetconnectdSettingsPlugin(octoprint.plugin.SettingsPlugin,
                                octoprint.plugin.TemplatePlugin,
                                octoprint.plugin.SimpleApiPlugin,
                                octoprint.plugin.AssetPlugin):

	def __init__(self):
		self.address = None
		
	# Additional permissions hook

	def initialize(self):
		self.address = self._settings.get(["socket"])

	def get_additional_permissions(self):
		return [
			dict(key="ACCESS",
			     name="WIFI Setup Access",
			     description=gettext("Allows access to WIFI setup"),
			     roles=["access"],
			     dangerous=True,
			     default_groups=[USER_GROUP])
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
			socket="/var/run/netconnectd.sock",
			hostname=None,
			timeout=10
		)

	##~~ TemplatePlugin API

	def get_template_configs(self):
		return [
			dict(type="settings", name="Network connection")
		]

	##~~ SimpleApiPlugin API

	def get_api_commands(self):
		return dict(
			start_ap=[],
			stop_ap=[],
			refresh_wifi=[],
			configure_wifi=[],
			forget_wifi=[],
			reset=[]
		)

	def is_api_adminonly(self):
		return False

	def on_api_get(self, request):
		try:
			status = self._get_status()
			if status["wifi"]["present"]:
				wifis = self._get_wifi_list()
			else:
				wifis = []
		except Exception as e:
			return jsonify(dict(error=str(e)))

		return jsonify(dict(
			wifis=wifis,
			status=status,
			hostname=self.hostname
		))

	def on_api_command(self, command, data):
		if command == "refresh_wifi":
			return jsonify(self._get_wifi_list(force=True))

		# any commands processed after this check require admin permissions
		if not admin_permission.can():
			return make_response("Insufficient rights", 403)

		if command == "configure_wifi":
			if data["psk"]:
				self._logger.info("Configuring wifi {ssid} and psk...".format(**data))
			else:
				self._logger.info("Configuring wifi {ssid}...".format(**data))

			self._configure_and_select_wifi(data["ssid"], data["psk"], force=data["force"] if "force" in data else False)

		elif command == "forget_wifi":
			self._forget_wifi()

		elif command == "reset":
			self._reset()

		elif command == "start_ap":
			self._start_ap()

		elif command == "stop_ap":
			self._stop_ap()

	##~~ AssetPlugin API

	def get_assets(self):
		return dict(
			js=["js/netconnectd.js"],
			css=["css/netconnectd.css"],
			less=["less/netconnectd.less"]
		)

	##~~ Private helpers

	def _get_wifi_list(self, force=False):
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
		

	def _get_status(self):
        mac_addr_pattern = r"[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}"
        iwconfig_re = re.compile('ESSID:"(?P<ssid>[^"]+)".*Access Point: (?P<address>%s).*' % mac_addr_pattern , re.DOTALL)

        iwconfig_run = subprocess.Popen(['sudo', '/sbin/iwconfig', 'wlan0'])
        iwconfig_output, err = iwlist_raw.communicate()
        retcode = iwlist_raw.poll()
        if retcode:
		    self._logger.info("Error while checking status: retcode = " + retcode)
            return None, None

        m = iwconfig_re.search(iwconfig_output)
        if not m:
            return None, None

        return m.group('ssid'), m.group('address')

	def _configure_and_select_wifi(self, ssid, psk, force=False):
	
        temp_conf_file = open('wpa_supplicant.conf.tmp', 'w')

        temp_conf_file.write('ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n')
        temp_conf_file.write('update_config=1\n')
        temp_conf_file.write('\n')
        temp_conf_file.write('network={\n')
        temp_conf_file.write('	ssid="' + ssid + '"\n')

        if psk == '':
            temp_conf_file.write('	key_mgmt=NONE\n')
        else:
            temp_conf_file.write('	psk="' + psk + '"\n')

        temp_conf_file.write('	}')

        temp_conf_file.close

        os.system('mv wpa_supplicant.conf.tmp /etc/wpa_supplicant/wpa_supplicant.conf')
		time.sleep(1)
        os.system('sudo wpa_cli -i wlan0 reconfigure')
		
        os.system('ifconfig wlan0 down')
		time.sleep(2)
        os.system('ifconfig wlan0 up')
	
	def _forget_wifi(self):
        temp_conf_file = open('wpa_supplicant.conf.tmp', 'w')

        temp_conf_file.write('ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n')
        temp_conf_file.write('update_config=1\n')
        temp_conf_file.write('\n')

        temp_conf_file.close

        os.system('mv wpa_supplicant.conf.tmp /etc/wpa_supplicant/wpa_supplicant.conf')
		time.sleep(1)
        os.system('sudo wpa_cli -i wlan0 reconfigure')
		
        os.system('ifconfig wlan0 down')
		time.sleep(2)
        os.system('ifconfig wlan0 up')

	def _reset(self):
        os.system('sudo wpa_cli -i wlan0 reconfigure')
		
        os.system('ifconfig wlan0 down')
		time.sleep(2)
        os.system('ifconfig wlan0 up')

	def _start_ap(self):
        os.system('sudo wpa_cli -i wlan0 reconfigure')
		
        os.system('ifconfig wlan0 down')
		time.sleep(2)
        os.system('ifconfig wlan0 up')

	def _stop_ap(self):
        os.system('sudo wpa_cli -i wlan0 reconfigure')
		
        os.system('ifconfig wlan0 down')
		time.sleep(2)
        os.system('ifconfig wlan0 up')

	def _send_message(self, message, data):
		obj = dict()
		obj[message] = data

		import json
		js = json.dumps(obj, encoding="utf8", separators=(",", ":"))

		import socket
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		sock.settimeout(self._settings.get_int(["timeout"]))
		try:
			sock.connect(self.address)
			sock.sendall(js + '\x00')

			buffer = []
			while True:
				chunk = sock.recv(16)
				if chunk:
					buffer.append(chunk)
					if chunk.endswith('\x00'):
						break

			data = ''.join(buffer).strip()[:-1]

			response = json.loads(data.strip())
			if "result" in response:
				return True, response["result"]

			elif "error" in response:
				# something went wrong
				self._logger.warn("Request to netconnectd went wrong: " + response["error"])
				return False, response["error"]

			else:
				output = "Unknown response from netconnectd: {response!r}".format(response=response)
				self._logger.warn(output)
				return False, output

		except Exception as e:
			output = "Error while talking to netconnectd: {}".format(e)
			self._logger.warn(output)
			return False, output

		finally:
			sock.close()

__plugin_name__ = "Netconnectd Client"
__plugin_author__ = "Gina Häußge & Mehmet Sutas"
__plugin_description__ = "Setup wifi credentiials"
__plugin_disabling_discouraged__ = gettext("Without this plugin you will no longer be able to setup "
                                           "wifi credentials through Octoprint UI.")
__plugin_license__ = "AGPLv3"
#__plugin_implementation__ = BackupPlugin()
__plugin_hooks__ = {
	"octoprint.access.permissions": __plugin_implementation__.get_additional_permissions
}

def __plugin_check__():
	import sys
	if sys.platform == 'linux2':
		return True

	logging.getLogger("octoprint.plugins." + __name__).warn("The netconnectd plugin only supports Linux")
	return False

def __plugin_load__():
	# since we depend on a Linux environment, we instantiate the plugin implementation here since this will only be
	# called if the OS check above was successful
	global __plugin_implementation__
	__plugin_implementation__ = NetconnectdSettingsPlugin()
	return True



