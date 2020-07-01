# coding=utf-8
import setuptools
import octoprint_setuptools

setuptools.setup(**octoprint_setuptools.create_plugin_setup_parameters(
	identifier="wifisetup",
	name="OctoPrint-Wifisetup",
	version="0.2",
	description="Plugin for recording Wifi psk through OctoPrint's interface. It's only available for Linux right now.",
	author="Mehmet Sutas based on Netconnectd of Gina Häußge",
	mail="osd@foosel.net",
	url="http://github.com/OctoPrint/OctoPrint-Netconnectd",
	requires=[
		"OctoPrint"
	]
))
