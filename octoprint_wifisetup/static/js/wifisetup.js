$(function() {
    function WifisetupViewModel(parameters) {
        var self = this;
        
        self.sleep = function(ms) {
            const date = Date.now();
            let currentDate = null;
            do {
                currentDate = Date.now();
            } while (currentDate - date < ms);
        };

        self.loginState = parameters[0];
        self.settingsViewModel = parameters[1];

        self.pollingEnabled = false;
        self.pollingTimeoutId = undefined;

        self.reconnectInProgress = false;
        self.reconnectTimeout = undefined;

        self.enableQualitySorting = ko.observable(false);

        self.hostname = ko.observable();
        self.status = {
            link: ko.observable(),
            connections: {
                ap: ko.observable(),
                wifi: ko.observable(),
                wired: ko.observable()
            },
            wifi: {
                current_ssid: ko.observable(),
                present: ko.observable()
            }
        };
        self.statusCurrentWifi = ko.observable();

        self.editorWifi = undefined;
        self.editorWifiSsid = ko.observable();
        self.editorWifiSsid1 = ko.observable();
        self.editorWifiPassphrase1 = ko.observable();

        self.working = ko.observable(false);
        self.error = ko.observable(false);

        self.connectionStateText = ko.computed(function() {
            var text;

            if (self.error()) {
                text = gettext("Hata!");
            } else if (self.status.wifi.current_ssid()) {
                text = _.sprintf(gettext("WIFI bağlantısı mevcut. (SSID \"%(ssid)s\")"), {ssid: self.status.wifi.current_ssid()});
            } else if (self.status.connections.ap()) {
                text = gettext("Rigid3D hotspot aktif. Şifre: 12345678");
            } else if (!(self.status.wifi.present())) {
                text = gettext("Wifi yayını devre dışı. Gelişmiş seçeneklerden açabilirsiniz.");
			} else {
                text = gettext("WIFI bağlantısı yok.");
			}
            return text;
        });

        self.daemonOnline = ko.computed(function() {
            return (!(self.error()));
        });
        
        self.radioStatus = ko.computed(function() {
            return self.status.wifi.present();
        });

        self.apStatus = ko.computed(function() {
            return self.status.connections.ap();
        });

        // initialize list helper
        self.listHelper = new ItemListHelper(
            "wifis",
            {
                "ssid": function (a, b) {
                    // sorts ascending
                    if (a["ssid"].toLocaleLowerCase() < b["ssid"].toLocaleLowerCase()) return -1;
                    if (a["ssid"].toLocaleLowerCase() > b["ssid"].toLocaleLowerCase()) return 1;
                    return 0;
                },
                "quality": function (a, b) {
                    // sorts descending
                    if (a["quality"] > b["quality"]) return -1;
                    if (a["quality"] < b["quality"]) return 1;
                    return 0;
                }
            },
            {
            },
            "quality",
            [],
            [],
            10
        );

        self.getEntryId = function(data) {
            return "tab_plugin_wifisetup_wifi_" + md5(data.ssid);
        };

        self.refresh = function() {
            self.requestData();
        };

        self.fromResponse = function (response) {
            if (response.error !== undefined) {
                self.error(true);
                return;
            } else {
                self.error(false);
            }

            self.hostname(response.hostname);

            self.status.link(false);
            self.status.connections.ap(response.status.ap);
            self.status.connections.wifi(response.status.wifi);
            self.status.connections.wired(response.status.wired);
            self.status.wifi.current_ssid(response.status.ssid);
            self.status.wifi.present(response.wifiradio);
			
            self.statusCurrentWifi(undefined);
            if (response.status.ssid) {
                _.each(response.wifis, function(wifi) {
                    if (wifi.ssid == response.status.ssid) {
                        self.statusCurrentWifi(self.getEntryId(wifi));
                    }
                });
            }

            var enableQualitySorting = false;
            _.each(response.wifis, function(wifi) {
                if (wifi.quality != undefined) {
                    enableQualitySorting = true;
                }
            });
            self.enableQualitySorting(enableQualitySorting);

            var wifis = [];
            _.each(response.wifis, function(wifi) {
                var qualityInt = parseInt(wifi.quality);
                var quality = undefined;
                if (!isNaN(qualityInt)) {
                    quality = qualityInt;
                }

                wifis.push({
                    ssid: wifi.ssid,
                    address: wifi.address,
                    encrypted: wifi.encrypted,
                    quality: quality,
                    qualityText: (quality != undefined) ? quality : undefined
                });
            });

            self.listHelper.updateItems(wifis);
            if (!enableQualitySorting) {
                self.listHelper.changeSorting("ssid");
            }

            if (self.pollingEnabled) {
                self.pollingTimeoutId = setTimeout(function() {
                    self.requestData();
                }, 30000)
            }
        };

        self.configureWifi = function(data) {
            //if (!self.loginState.isAdmin()) return;
			
            self.editorWifi = data;
            self.editorWifiSsid(data.ssid);
            self.editorWifiPassphrase1(undefined);
            if (data.encrypted) {
                $("#tab_plugin_wifisetup_wificonfig").modal("show");
            } else {
                self.confirmWifiConfiguration();
            }
        };
        
        self.blindConfigureWifi = function() {
            //if (!self.loginState.isAdmin()) return;
			
            self.editorWifiSsid1(undefined);
            self.editorWifiPassphrase1(undefined);
            $("#tab_plugin_wifisetup_blindconfig").modal("show");
        };

        self.sendWifiRefresh = function(force) {
            if (force === undefined) force = false;
            self._postCommand("list_wifi", {force: force}, function(response) {
                self.fromResponse({"wifis": response});
            });
        };

        self.confirmWifiConfiguration = function() {
            self.sendWifiConfig(self.editorWifiSsid(), self.editorWifiPassphrase1(), function() {
                self.editorWifi = undefined;
                self.editorWifiSsid(undefined);
                self.editorWifiPassphrase1(undefined);
                $("#tab_plugin_wifisetup_wificonfig").modal("hide");
            });
//            $("#tab_plugin_wifisetup_wificonfig").modal("hide");
            self.sleep(3000);
            self.refresh();
//            self.working(false);
        };
        
        self.blindConfirmWifiConfiguration = function() {
            self.sendWifiConfig(self.editorWifiSsid1(), self.editorWifiPassphrase1(), function() {
                self.editorWifi = undefined;
                self.editorWifiSsid(undefined);
                self.editorWifiSsid1(undefined);
                self.editorWifiPassphrase1(undefined);
                $("#tab_plugin_wifisetup_blindconfig").modal("hide");
            });
//            $("#tab_plugin_wifisetup_blindconfig").modal("hide");
            self.sleep(3000);
            self.refresh();
//            self.working(false);
        };

        self.sendWifiConfig = function(ssid, psk, successCallback, failureCallback) {
            //if (!self.loginState.isAdmin()) return;
			
            self.working(true);
            self._postCommand("configure_wifi", {ssid: ssid, psk: psk}, successCallback, failureCallback, function() {
                self.working(false);
                if (self.reconnectInProgress) {
                    self.tryReconnect();
                }
            }, 10000);
        };

        self.sendForgetWifi = function() {
            //if (!self.loginState.isAdmin()) return;
            self.working(true);
            self._postCommand("forget_wifi", {});
            self.sleep(3000);
            self.working(false);
            self.refresh();
        };
        
        self.radioOn = function() {
            //if (!self.loginState.isAdmin()) return;
            self.working(true);
            self._postCommand("radio_on", {});
            self.sleep(3000);
            self.working(false);
            self.refresh();
        };
        
        self.radioOff = function() {
            //if (!self.loginState.isAdmin()) return;
            self.working(true);
            self._postCommand("radio_off", {});
            self.sleep(3000);
            self.working(false);
            self.refresh();
        };
        
        self.apOff = function() {
            //if (!self.loginState.isAdmin()) return;
            self.working(true);
            self._postCommand("ap_off", {});
            self.sleep(3000);
            self.working(false);
            self.refresh();
        };
        
        self.tryReconnect = function() {
            var hostname = self.hostname();

            var location = window.location.href
            location = location.replace(location.match("https?\\://([^:@]+(:[^@]+)?@)?([^:/]+)")[3], hostname);

            var pingCallback = function(result) {
                if (!result) {
                    return;
                }

                if (self.reconnectTimeout != undefined) {
                    clearTimeout(self.reconnectTimeout);
                    window.location.replace(location);
                }
                hideOfflineOverlay();
                self.reconnectInProgress = false;
            };

            ping(location, pingCallback);
            self.reconnectTimeout = setTimeout(self.tryReconnect, 1000);
        };

        self._postCommand = function (command, data, successCallback, failureCallback, alwaysCallback, timeout) {
            var payload = _.extend(data, {command: command});

            var params = {
                url: API_BASEURL + "plugin/wifisetup",
                type: "POST",
                dataType: "json",
                data: JSON.stringify(payload),
                contentType: "application/json; charset=UTF-8",
                success: function(response) {
                    if (successCallback) successCallback(response);
                },
                error: function() {
                    if (failureCallback) failureCallback();
                },
                complete: function() {
                    if (alwaysCallback) alwaysCallback();
                }
            };

            if (timeout != undefined) {
                params.timeout = timeout;
            }

            $.ajax(params);
        };

        self.requestData = function () {
            if (self.pollingTimeoutId != undefined) {
                clearTimeout(self.pollingTimeoutId);
                self.pollingTimeoutId = undefined;
            }
			
            $.ajax({
                url: API_BASEURL + "plugin/wifisetup",
                type: "GET",
                dataType: "json",
                success: self.fromResponse
            });
        };

        self.onUserLoggedIn = function(user) {
            //if (user.admin) {
                self.requestData();
           // }
        };

        self.onBeforeBinding = function() {
            self.settings = self.settingsViewModel.settings;
        };

        self.onSettingsShown = function() {
            self.pollingEnabled = true;
            self.requestData();
        };

        self.onSettingsHidden = function() {
            if (self.pollingTimeoutId != undefined) {
                self.pollingTimeoutId = undefined;
            }
            self.pollingEnabled = false;
        };

        self.onServerDisconnect = function() {
            return !self.reconnectInProgress;
        }

    }

    // view model class, parameters for constructor, container to bind to
    OCTOPRINT_VIEWMODELS.push({
        construct: WifisetupViewModel,
        dependencies: ["loginStateViewModel", "settingsViewModel"],
        elements: ["#tab_plugin_wifisetup"]
    });
});
