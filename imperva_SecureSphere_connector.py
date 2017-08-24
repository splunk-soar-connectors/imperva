from phantom.action_result import ActionResult
import phantom.app as phantom
from phantom.base_connector import BaseConnector


import ss


class imperva_SecureSphere_connector(BaseConnector):

    BANNER = "Imperva SecureSphere Connector"

    def initialize(self):
        self.set_validator("ip", self._validate_ip)

        return phantom.APP_SUCCESS

    def finalize(self):
        return

    def handle_exception(self, exception_object):
        """All the code within BaseConnector::_handle_action is within a 'try:
        except:' clause. Thus if an exception occurs during the execution of
        this code it is caught at a single place. The resulting exception
        object is passed to the AppConnector::handle_exception() to do any
        cleanup of it's own if required. This exception is then added to the
        connector run result and passed back to spawn, which gets displayed
        in the Phantom UI.
        """

        return

    def _validate_ip(self, param):
        if "/" in param:
            parts = param.split('/')
            if(
                len(parts) == 2
                and phantom.is_ip(parts[0])
                and parts[1].isdigit()
            ):
                return True
        elif phantom.is_ip(param):
            return True

        return False

    def _test_connectivity(self, param):

        config = self.get_config()
        MX = ss.SecureSphere(
            config.get("mxAddress"),
            config.get("mxPort"),
            config.get("mxUsername"),
            config.get("mxPassword"),
            config.get("verifyCert")
        )

        if not MX.login():
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                MX.ResponseString
            )
        else:
            return self.set_status_save_progress(
                phantom.APP_SUCCESS,
                "Successful login"
            )

    def handle_action(self, param):

        action_id = self.get_action_identifier()

        supported_actions = {
            "test connectivity": self._test_connectivity,
            "block ip": self.block_ip,
            "unblock ip": self.unblock_ip
        }

        run_action = supported_actions[action_id]

        return run_action(param)

    def _modifyBlock(self, param, action):
        response = ""

        config = self.get_config()
        MX = ss.SecureSphere(
            config.get("mxAddress"),
            config.get("mxPort"),
            config.get("mxUsername"),
            config.get("mxPassword"),
            config.get("verifyCert")
        )

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not MX.login():
            action_result.set_status(phantom.APP_ERROR)
        else:

            if action == "add":
                # Create Phantom Blacklist Policy in SecureSphere
                response = MX.CreateIpBlockingPolicy(
                    config.get("ipGroupName"),
                    config.get("policyName")
                )

            # If call policy creation succeeded, or the policy already exists
            # or this is an unblock action
            if(action == "remove"
               or response == "Success"
               or "IMP-10005" in str(response)):

                ip = param["ip"]

                response = MX.ModifyIpList(
                    config.get("ipGroupName"),
                    [ip],
                    action
                )
            else:
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Creating Blocking Policy",
                    str(response)
                )

        summary = {
            "status_error": str(MX.Error),
            "status_code": MX.ResponseCode,
            "status_string": MX.ResponseString
        }

        if(MX.Error):
            action_result.set_status(
                phantom.APP_ERROR,
                "Error modifying ip group",
                str(response)
            )
        else:
            action_result.set_status(
                phantom.APP_SUCCESS
            )

        action_result.update_summary(summary)

        return

    def unblock_ip(self, param):

        self._modifyBlock(param, "remove")
        return

    def block_ip(self, param):

        self._modifyBlock(param, "add")
        return


# ==========================================================================================
# Logic for testing interactively e.g. python2.7 ./imperva_SecureSphere_connector.py ./test_jsons/reject.json
# ==========================================================================================
"""
if __name__ == '__main__':

    import sys
    # import pudb                                          # executes a runtime breakpoint and brings up the pudb debugger.
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:                           # input a json file that contains data like the configuration and action parameters,
        in_json = f.read()
        in_json = json.loads(in_json)
        print ("%s %s" % (sys.argv[1], json.dumps(in_json, indent=4)))

        connector = imperva_SecureSphere_connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ("%s %s" % (connector.BANNER, json.dumps(json.loads(ret_val), indent=4)))

    exit(0)
"""
