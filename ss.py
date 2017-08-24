import base64
import itertools
import json
import requests


class SecureSphere(object):

    def __init__(
        self, IP, Port, User, Password, verifyCert=False, Version="v1"
    ):
        self.IP = ""
        self.Port = Port
        self.IsAuthenticated = False
        self.AuthToken = ""
        self.BaseURL = (
            "https://" + IP + ":" + Port + "/SecureSphere/api/" + Version
        )
        self.User = User
        self.Password = Password
        self.Error = False
        self.ResponseCode = None
        self.ResponseString = None
        self.verifyCert = verifyCert

    def login(self):
        AuthString = self.User+":"+self.Password
        Headers = {
            "Authorization": "Basic "
                             + base64.b64encode(AuthString.encode("utf-8"))
                             .decode("utf-8")
        }
        try:
            r = requests.post(
                self.BaseURL + "/auth/session",
                headers=Headers,
                verify=self.verifyCert
            )
            r.raise_for_status()
        except requests.exceptions.SSLError as e:
            self.ResponseCode = "500"
            self.ResponseString = (
                "Error connecting to API - "
                "Likely due to the 'validate server certificate' option. "
                "Details: " + str(e)
            )

            return False
        except requests.exceptions.RequestException as e:
            self.Error = True
            if r is None:
                self.ResponseCode = r.status_code
                self.ResponseString = r.reason + e.message
            else:
                self.ResponseCode = "500"
                self.ResponseString = e.message

            return False
        except Exception as e:
            self.Error = True
            self.ResponseCode = '500'
            self.ResponseString = e.message

            return False

        else:
            self.ResponseCode = r.status_code
            self.ResponseString = r.reason
            if r.status_code != 200:
                self.Error = True
                return False
            else:
                self.AuthToken = r.json()["session-id"]
                self.IsAuthenticated = True
                self.Error = False

        return not(self.Error)

    def logout(self):

        Headers = {"Cookie": self.AuthToken}
        try:
            r = requests.delete(
                self.BaseURL + "/auth/session",
                headers=Headers,
                verify=self.verifyCert
            )
            r.raise_for_status()
        except requests.exceptions.SSLError as e:
            self.ResponseCode = "500"
            self.ResponseString = (
                "Error connecting to API - "
                "Likely due to the 'validate server certificate' option. "
                "Details: " + str(e)
            )

            return False
        except requests.exceptions.RequestException as e:
            self.Error = True
            self.ResponseCode = r.status_code
            self.ResponseString = r.reason + e.message

            return False
        except Exception as e:
            self.Error = True
            self.ResponseCode = '500'
            self.ResponseString = e.message

            return False

        else:
            self.ResponseCode = r.status_code
            self.ResponseString = r.reason
            if(r.status_code != 200):
                self.Error = True
                return False
            else:
                self.AuthToken = r.json()["session-id"]
                self.IsAuthenticated = True
                self.Error = False

        return not(self.Error)

    def _SendRequest(self, URL, method, payload=None, ContentType=None):
        results = None

        # setup
        URL = self.BaseURL + URL

        Headers = {
            "Cookie": self.AuthToken,
            "Content-Type": ContentType
        }

        try:
            if(method == "GET"):
                r = requests.get(
                    URL,
                    headers=Headers,
                    data=payload,
                    verify=self.verifyCert
                )
            elif(method == "POST"):
                r = requests.post(
                    URL,
                    headers=Headers,
                    data=payload,
                    verify=self.verifyCert
                )
            elif(method == "DELETE"):
                r = requests.post(
                    URL,
                    headers=Headers,
                    data=payload,
                    verify=self.verifyCert
                )
            elif(method == "PUT"):
                r = requests.put(
                    URL,
                    headers=Headers,
                    data=payload,
                    verify=self.verifyCert
                )
            else:
                return False

            r.raise_for_status()
        except requests.exceptions.SSLError as e:
            self.ResponseCode = "500"
            self.ResponseString = (
                "Error connecting to API - "
                "Likely due to the 'validate server certificate' option. "
                "Details: " + str(e)
            )

            return False
        except requests.exceptions.RequestException as e:
            # populate the internal error facility
            self.ResponseCode = r.status_code
            self.ResponseString = r.reason
            self.Error = True

            # Handle nicely the errors we know about
            # reraise at the end otherwise
            if r.status_code == 401:
                results = None
            elif r.status_code == 406:
                try:
                    results = r.json()
                except Exception as e:
                    results = r.text
            else:
                results = r.text
        except Exception as e:
            self.ResponseCode = '500'
            self.ResponseString = 'Error calling "' + URL + '".' + e.message
            self.Error = True
        else:

            # populate the internal response facility
            self.ResponseCode = r.status_code
            self.ResponseString = r.reason

            # 200 is our only successful error code
            if r.status_code == 200:
                self.Error = False
            else:
                self.Error = True

            try:
                results = r.json()
            except Exception as e:
                results = r.text

        return results

    def _CullList(self, ips, ipGroupName):
        # Get all existing entries in th IP Group
        currentEntries = self.GetAllEntriesInIpGroup(ipGroupName)

        # Separate out the IPs and Networks (without CIDR mask)
        currentIpList = [
            x["networkAddress" if "networkAddress" in x else "ipAddressFrom"]
            for x in currentEntries
        ]

        # Separate out all Networks
        currentNetworkList = [
            x for x in currentEntries if "networkAddress" in x
        ]

        # Get Just the IPs from the list of requested Adds
        newIps = [
            x if "/" not in x else x.split("/")[0] for x in ips
        ]

        # Find if any of the IPs exist or belong to an already blocked network
        overlapList = [i for i in ips if i in currentIpList] + [
            n for n, x in list(itertools.product(newIps, currentNetworkList))
            if self._IsIpInSubnet(n, x["networkAddress"], x["cidrMask"])
        ]

        # Cull the list to get just those that don't exist in the IP
        # Group already
        leftovers = [
            i for i in ips
            if (i if "/" not in i else i.split("/")[0]) not in overlapList
        ]

        return leftovers

    def _IpToInt(self, ip):
        o = map(int, ip.split('.'))
        res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
        return res

    def _IsIpInSubnet(self, ip, ipNetwork, maskLength):

        ipInt = self._IpToInt(ip)
        maskLengthFromRight = 32 - maskLength

        # convert network to integer form
        ipNetworkInt = self._IpToInt(ipNetwork)

        # convert to binary
        binString = "{0:b}".format(ipNetworkInt)

        chopAmount = 0
        for i in range(maskLengthFromRight):
            if i < len(binString):
                chopAmount += int(binString[len(binString) - 1 - i]) * 2 ** i

        minVal = ipNetworkInt-chopAmount
        maxVal = minVal + 2 ** maskLengthFromRight - 1

        return minVal <= ipInt and ipInt <= maxVal

    def GetAllEntriesInIpGroup(self, ipGroupName):
        ResponseJSON = self._SendRequest(
            "/conf/ipGroups/"+ipGroupName+"/data",
            "GET"
        )

        if self.Error:
            return ResponseJSON
        else:
            return ResponseJSON["entries"]

    def GetAllSites(self):
        ResponseJSON = self._SendRequest(
            "/conf/sites",
            "GET"
        )

        if self.Error:
            return ResponseJSON
        else:
            return ResponseJSON["sites"]

    def GetAllServerGroups(self, Site):
        ResponseJSON = self._SendRequest(
            "/conf/serverGroups/"+Site,
            "GET"
        )

        if self.Error:
            return ResponseJSON
        else:
            return ResponseJSON["server-groups"]

    def GetAllWebServices(self, Site, ServerGroup):
        ResponseJSON = self._SendRequest(
            "/conf/webServices/"+Site+"/"+ServerGroup,
            "GET"
        )

        if self.Error:
            return ResponseJSON
        else:
            return ResponseJSON["web-services"]

    def ModifyIpList(self, ipGroupName, ips, action):
        entries = []
        actionResponse = ""

        if action == "add":
            actionResponse = (
                "IP/Network successfully added to IP Group '"
                + ipGroupName + "'"
            )
        else:
            actionResponse = (
                "IP/Network successfully removed from IP Group '"
                + ipGroupName + "'"
            )

        if action == "add":
            ips = self._CullList(ips, ipGroupName)
        if len(ips) > 0:
            for ip in ips:
                if "/" in ip:
                    entries.append({
                        "networkAddress": ip.split("/")[0],
                        "cidrMask": ip.split("/")[1],
                        "type": "network",
                        "operation": action
                    })
                else:
                    entries.append({
                        "ipAddressFrom": ip,
                        "type": "single",
                        "operation": action
                    })

            JSON = {
                "entries": entries
            }

            ResponseJSON = self._SendRequest(
                "/conf/ipGroups/"+ipGroupName+"/data",
                "PUT",
                json.dumps(JSON),
                "application/json"
            )
        elif action == "add":
            self.Error = False
            self.ResponseCode = "200"
            actionResponse = (
                "IP/Network already being blocked by IP "
                "Group - '" + ipGroupName
            )
            ResponseJSON = {"ssMessage": "None Added"}

        if(
            action == "remove"
            and ResponseJSON is not None
            and "IMP-10602" in str(ResponseJSON)
        ):
            self.Error = False
            self.ResponseCode = "200"
            actionResponse = (
                "IP/Network does not exist in IP Group '" + ipGroupName + "'"
            )

        if self.Error:
            return ResponseJSON
        else:
            self.ResponseString = actionResponse
            return "Success"

    def CreateIpBlockingPolicy(self, ipGroupName, policyName):
        applyToList = []
        siteList = self.GetAllSites()
        ResponseJSON = ""

        # traverse site tree to get all web services from SecureSphere so we
        # can apply new policy to each of them
        for site in siteList:
            serverGroups = self.GetAllServerGroups(site)
            for serverGroup in serverGroups:
                webServices = self.GetAllWebServices(site, serverGroup)
                for webService in webServices:
                    applyToList.append(
                        {"siteName": site,
                         "serverGroupName": serverGroup,
                         "webServiceName": webService}
                    )

        if len(applyToList) > 0:
            JSON = {
                "enabled": "true",
                "oneAlertPerSession": "false",
                "displayResponsePage": "false",
                "severity": "medium",
                "action": "block",
                "followedAction": None,
                "matchCriteria": [{
                    "ipGroups": [ipGroupName],
                    "type": "sourceIpAddresses",
                    "operation": "atLeastOne",
                }],
                "applyTo": applyToList
            }
            ResponseJSON = self._SendRequest(
                "/conf/webServiceCustomPolicies/"+policyName,
                "POST",
                json.dumps(JSON),
                "application/json"
            )

        else:
            self.ResponseCode = "500"
            self.Error = True
            self.ResponseString = "No sites available to apply policy."
            ResponseJSON = {"ssMessage": "Failed"}

        # 404 indicates that creating a policy on the fly is not supported in
        # this patch version
        if self.ResponseCode == "404":
            self.ResponseString = "This version of the product does not "
            + "support the create of security Policies via API. Please add "  # pylint: disable=E1130
            + "the '"+policyName+"' policy manually, and ensure it references "  # pylint: disable=E1130
            + "the '"+ipGroupName+"' for proper blocking."  # pylint: disable=E1130
            ResponseJSON = {"ssMessage": "Failed"}

        if self.Error:
            return ResponseJSON
        else:
            return "Success"

    def modify_blocking_policy(self, ipGroupName, policyName):
        applyToList = []
        siteList = self.GetAllSites()
        ResponseJSON = ""

        if len([0,0,0]) > 0:
            JSON = {
                "action": "block",
            }
            ResponseJSON = self._SendRequest(
                "/conf/webServiceCustomPolicies/"+policyName,
                "PUT",
                json.dumps(JSON),
                "application/json"
            )

        else:
            self.ResponseCode = "500"
            self.Error = True
            self.ResponseString = "No sites available to apply policy."
            ResponseJSON = {"ssMessage": "Failed"}

        # 404 indicates that creating a policy on the fly is not supported in
        # this patch version
        if self.ResponseCode == "404":
            self.ResponseString = "This version of the product does not "
            + "support the create of security Policies via API. Please add "  # pylint: disable=E1130
            + "the '"+policyName+"' policy manually, and ensure it references "  # pylint: disable=E1130
            + "the '"+ipGroupName+"' for proper blocking."  # pylint: disable=E1130
            ResponseJSON = {"ssMessage": "Failed"}

        if self.Error:
            return ResponseJSON
        else:
            return "Success"
