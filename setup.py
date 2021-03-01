# coding=utf-8
import setuptools
import octoprint_setuptools

setuptools.setup(**octoprint_setuptools.create_plugin_setup_parameters(
	identifier="wifisetup",
	name="OctoPrint-Wifisetup",
	version="0.3",
	description="Plugin for recording Wifi psk through OctoPrint's interface. It's only available for Debian Linux with nmcli right now. Derived from Netconnectd plugin of Gina Häußge",
	author="Mehmet Sutas",
	mail="msutas@rigid3d.com",
	url="https://github.com/msutas/Wifisetup",
	requires=[
		"OctoPrint"
	]
))
