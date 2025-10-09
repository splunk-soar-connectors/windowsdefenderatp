# File: microsoftdefenderforendpoint_connector.py
#
# Copyright (c) 2019-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import gzip
import json
import os
import re
import shutil
import sys
import time
import uuid
from copy import deepcopy

import phantom.rules as ph_rules
from phantom.vault import Vault as Vault


try:
    from urllib.parse import quote, unquote, urlencode
except Exception:
    from urllib import quote, unquote, urlencode

import grp
import ipaddress
import pwd
from datetime import datetime, timedelta, timezone

import encryption_helper
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from django.http import HttpResponse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from microsoftdefenderforendpoint_consts import *


def _handle_login_redirect(request, key):
    """This function is used to redirect login request to Microsoft login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url/admin_consent_url
    """

    asset_id = request.GET.get("asset_id")
    if not asset_id:
        return HttpResponse("ERROR: Asset ID not found in URL", content_type="text/plain", status=400)
    state = _load_app_state(asset_id)
    if not state:
        return HttpResponse("ERROR: Invalid asset_id", content_type="text/plain", status=400)
    url = state.get(key)
    if not url:
        return HttpResponse(f"App state is invalid, {key} not found.", content_type="text/plain", status=400)
    response = HttpResponse(status=302)
    response["Location"] = url
    return response


def _load_app_state(asset_id, app_connector=None):
    """This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print("In _load_app_state: Invalid asset_id")
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = f"{app_dir}/{asset_id}_state.json"
    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print("In _load_app_state: Invalid asset_id")
        return {}

    state = {}
    try:
        with open(real_state_file_path) as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.error_print(f"In _load_app_state: Exception: {e!s}")

    return state


def _save_app_state(state, asset_id, app_connector):
    """This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print("In _save_app_state: Invalid asset_id")
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = f"{app_dir}/{asset_id}_state.json"

    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print("In _save_app_state: Invalid asset_id")
        return {}

    try:
        with open(real_state_file_path, "w+") as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        print(f"Unable to save state file: {e!s}")

    return phantom.APP_SUCCESS


def _handle_login_response(request):
    """This function is used to get the login response of authorization request from Microsoft login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    asset_id = request.GET.get("state")
    if not asset_id:
        return HttpResponse(f"ERROR: Asset ID not found in URL\n{json.dumps(request.GET)}", content_type="text/plain", status=400)

    # Check for error in URL
    error = request.GET.get("error")
    error_description = request.GET.get("error_description")

    # If there is an error in response
    if error:
        message = f"Error: {error}"
        if error_description:
            message = f"{message} Details: {error_description}"
        return HttpResponse(f"Server returned {message}", content_type="text/plain", status=400)

    code = request.GET.get("code")

    # If code is not available
    if not code:
        return HttpResponse(f"Error while authenticating\n{json.dumps(request.GET)}", content_type="text/plain", status=400)

    state = _load_app_state(asset_id)
    state["code"] = code
    _save_app_state(state, asset_id, None)

    return HttpResponse("Code received. Please close this window, the action will continue to get new token.", content_type="text/plain")


def _handle_rest_request(request, path_parts):
    """Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: parts of the URL passed
    :return: dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse("error: True, message: Invalid REST endpoint request", content_type="text/plain", status=404)

    call_type = path_parts[1]

    # To handle authorize request in test connectivity action
    if call_type == "start_oauth":
        return _handle_login_redirect(request, "authorization_url")

    # To handle response from microsoft login page
    if call_type == "result":
        return_val = _handle_login_response(request)
        asset_id = request.GET.get("state")  # nosemgrep
        if asset_id and asset_id.isalnum():
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = f"{app_dir}/{asset_id}_{DEFENDERATP_TC_FILE}"
            real_auth_status_file_path = os.path.abspath(auth_status_file_path)
            if not os.path.dirname(real_auth_status_file_path) == app_dir:
                return HttpResponse("Error: Invalid asset_id", content_type="text/plain", status=400)
            open(auth_status_file_path, "w").close()
            try:
                uid = pwd.getpwnam("apache").pw_uid
                gid = grp.getgrnam("phantom").gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, "0664")
            except Exception:
                pass

        return return_val
    return HttpResponse("error: Invalid endpoint", content_type="text/plain", status=404)


def _get_dir_name_from_app_name(app_name):
    """Get name of the directory for the app.

    :param app_name: Name of the application for which directory name is required
    :return: app_name: Name of the directory for the application
    """

    app_name = "".join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if not app_name:
        app_name = "app_for_phantom"
    return app_name


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class WindowsDefenderAtpConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._state = None
        self._tenant = None
        self._client_id = None
        self._access_token = None
        self._refresh_token = None
        self._client_secret = None
        self._environment = None
        self._non_interactive = None
        self._graph_url = None
        self._login_url = None
        self._resource_url = None

    def decrypt_state(self, state, salt):
        """
        Decrypts the state.

        :param state: state dictionary
        :param salt: salt used for decryption
        :return: decrypted state
        """
        if not state.get("is_encrypted"):
            return state

        access_token = state.get("token", {}).get("access_token")
        if access_token:
            state["token"]["access_token"] = encryption_helper.decrypt(access_token, salt)

        refresh_token = state.get("token", {}).get("refresh_token")
        if refresh_token:
            state["token"]["refresh_token"] = encryption_helper.decrypt(refresh_token, salt)
        code = state.get("code")
        if code:
            state["code"] = encryption_helper.decrypt(code, salt)

        return state

    def encrypt_state(self, state, salt):
        """
        Encrypts the state.

        :param state: state dictionary
        :param salt: salt used for encryption
        :return: encrypted state
        """
        access_token = state.get("token", {}).get("access_token")
        if access_token:
            state["token"]["access_token"] = encryption_helper.encrypt(access_token, salt)

        refresh_token = state.get("token", {}).get("refresh_token")
        if refresh_token:
            state["token"]["refresh_token"] = encryption_helper.encrypt(refresh_token, salt)

        code = state.get("code")
        if code:
            state["code"] = encryption_helper.encrypt(code, salt)
            self.debug_print(f"Encrypted State Code: {state['code']}")

        state["is_encrypted"] = True

        return state

    def load_state(self):
        """
        Load the contents of the state file to the state dictionary and decrypt it.

        :return: loaded state
        """
        state = super().load_state()
        self.debug_print(f"Loaded App State: {state}")
        if not isinstance(state, dict):
            self.debug_print("Resetting the state file with the default format")
            state = {"app_version": self.get_app_json().get("app_version")}
            return state
        try:
            state = self.decrypt_state(state, self.get_asset_id())
        except Exception as e:
            self._dump_error_log(e, "Error while loading state file.")
            state = None

        return state

    def save_state(self, state):
        """
        Encrypt and save the current state dictionary to the the state file.

        :param state: state dictionary
        :return: status
        """
        try:
            state = self.encrypt_state(state, self.get_asset_id())
        except Exception as e:
            self._dump_error_log(e, "Error While saving state file.")
            return phantom.APP_ERROR

        return super().save_state(state)

    def _dump_error_log(self, error, message="Exception occurred."):
        self.error_print(message, dump_object=error)

    def _process_empty_response(self, response, action_result):
        """This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, f"Status Code: {response.status_code}. Error: Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        """This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as e:
            self._dump_error_log(e, "Error while processing HTML response.")
            error_text = "Cannot parse error details"

        if not error_text:
            error_text = "Error message unavailable. Please check the asset configuration and|or the action parameters"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            # Process a json response
            resp_json = response.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Unable to parse JSON response. Error: {self._get_error_message_from_exception(e)}"
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = None

        # Check whether the response contains error and error description fields
        # This condition will be used in test_connectivity
        if not isinstance(resp_json.get("error"), dict) and resp_json.get("error_description"):
            err = "Error:{}, Error Description:{} Please check your asset configuration parameters and run the test connectivity".format(
                resp_json.get("error"), resp_json.get("error_description")
            )
            message = f"Error from server. Status Code: {response.status_code} Data from server: {err}"

        # For other actions
        if isinstance(resp_json.get("error"), dict) and resp_json.get("error", {}).get("code"):
            msg = resp_json.get("error", {}).get("message")
            if "text/html" in msg:
                msg = BeautifulSoup(msg, "html.parser")
                for element in msg(["title"]):
                    element.extract()
                message = "Error from server. Status Code: {} Error Code: {} Data from server: {}".format(
                    response.status_code, resp_json.get("error", {}).get("code"), msg.text
                )
            else:
                message = "Error from server. Status Code: {} Error Code: {} Data from server: {}".format(
                    response.status_code, resp_json.get("error", {}).get("code"), msg
                )

        if not message:
            message = "Error from server. Status Code: {} Data from server: {}".format(
                response.status_code, response.text.replace("{", "{{").replace("}", "}}")
            )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the response_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": response.status_code})
            action_result.add_debug_data({"r_text": response.text})
            action_result.add_debug_data({"r_headers": response.headers})

        # Process each 'Content-Type' of response separately

        if "json" in response.headers.get("Content-Type", ""):
            return self._process_json_response(response, action_result)

        if "text/javascript" in response.headers.get("Content-Type", ""):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in response.headers.get("Content-Type", ""):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {} Data from server: {}".format(
            response.status_code, response.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _validate_integer(self, action_result, parameter, key, allow_zero=True):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

                parameter = int(parameter)
            except Exception as e:
                self._dump_error_log(e, "Error while validating integer parameter")
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

            # Negative value validation
            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key)), None

            # Zero value validation
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, POSITIVE_INTEGER_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        err_code = ERR_CODE_MSG
        err_msg = ERR_MSG_UNAVAILABLE

        self._dump_error_log(e, "Traceback: ")

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    err_code = e.args[0]
                    err_msg = e.args[1]
                elif len(e.args) == 1:
                    err_msg = e.args[0]
        except Exception as e:
            self._dump_error_log(e, "Error occurred while fetching exception information.")

        if not err_code:
            error_text = f"Error Message: {err_msg}"
        else:
            error_text = f"Error Code: {err_code}. Error Message: {err_msg}"

        return error_text

    def _is_ipv6(self, input_ip_address):
        """Function that checks given address and returns True if the address is a valid IPV6 address.
        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        # If interface is present in the IP, it will be separated by the %
        if "%" in input_ip_address:
            ip_address_input = input_ip_address.split("%")[0]

        try:
            ipaddress.ip_address(ip_address_input)
        except Exception as e:
            self._dump_error_log(e, "Error while validating IPv6.")
            return False

        return True

    def replace_null_values(self, data):
        return json.loads(json.dumps(data).replace("\\u0000", "\\\\u0000"))

    def _update_request(self, action_result, endpoint, headers=None, params=None, data=None, method="get"):
        """This function is used to update the headers with access_token before making REST call.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        if not headers:
            headers = {}

        if not self._non_interactive:
            token_data = {
                "client_id": self._client_id,
                "grant_type": DEFENDERATP_REFRESH_TOKEN_STRING,
                "refresh_token": self._refresh_token,
                "client_secret": self._client_secret,
                "resource": self._resource_url,
            }
        else:
            token_data = {
                "client_id": self._client_id,
                "grant_type": DEFENDERATP_CLIENT_CREDENTIALS_STRING,
                "client_secret": self._client_secret,
                "resource": self._resource_url,
            }

        if not self._access_token:
            if self._non_interactive:
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDERATP_TOKEN_NOT_AVAILABLE_MSG), None
            if not self._non_interactive and not self._refresh_token:
                # If none of the access_token and refresh_token is available
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDERATP_TOKEN_NOT_AVAILABLE_MSG), None

            # If refresh_token is available and access_token is not available, generate new access_token
            status = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(status):
                return action_result.get_status(), None

        headers.update({"Authorization": f"Bearer {self._access_token}", "Accept": "application/json", "Content-Type": "application/json"})

        ret_val, resp_json = self._make_rest_call(
            action_result=action_result, endpoint=endpoint, headers=headers, params=params, data=data, method=method
        )

        # If token is expired, generate new token
        if DEFENDERATP_TOKEN_EXPIRED in action_result.get_message():
            status = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(status):
                return action_result.get_status(), None

            headers.update({"Authorization": f"Bearer {self._access_token}"})

            ret_val, resp_json = self._make_rest_call(
                action_result=action_result, endpoint=endpoint, headers=headers, params=params, data=data, method=method
            )

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", verify=True):
        """Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None
        if headers is None:
            headers = {}

        try:
            request_func = getattr(requests, method)
        except AttributeError as e:
            self._dump_error_log(e, "Error occure while creating request object")
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"), resp_json)

        try:
            response = request_func(endpoint, data=data, headers=headers, verify=verify, params=params)

        except Exception as e:
            self._dump_error_log("Error occurred while logging the make_rest_call exception message")
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Error Connecting to server. Details: {self._get_error_message_from_exception(e)}"),
                resp_json,
            )

        return self._process_response(response, action_result)

    def _get_asset_name(self, action_result):
        """Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = DEFENDERATP_PHANTOM_ASSET_INFO_URL.format(asset_id=asset_id)
        url = f"{DEFENDERATP_PHANTOM_BASE_URL.format(phantom_base_url=self.get_phantom_base_url())}{rest_endpoint}"
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get("name")
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, f"Asset Name for id: {asset_id} not found.", None)
        return phantom.APP_SUCCESS, asset_name

    def _get_phantom_base_url_defenderatp(self, action_result):
        """Get base url of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of phantom
        """

        url = f"{DEFENDERATP_PHANTOM_BASE_URL.format(phantom_base_url=self.get_phantom_base_url())}{DEFENDERATP_PHANTOM_SYS_INFO_URL}"
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get("base_url")
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_app_rest_url(self, action_result):
        """Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_phantom_base_url_defenderatp(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None
        phantom_base_url = phantom_base_url.rstrip("/")
        self.save_progress(f"Using Phantom base URL as: {phantom_base_url}")
        app_json = self.get_app_json()
        app_name = app_json["name"]

        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = "{}/rest/handler/{}_{}/{}".format(phantom_base_url, app_dir_name, app_json["appid"], asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _generate_new_access_token(self, action_result, data):
        """This function is used to generate new access token using the code obtained on authorization.

        :param action_result: object of ActionResult class
        :param data: Data to send in REST call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """

        req_url = f"{self._login_url}{DEFENDERATP_SERVER_TOKEN_URL.format(tenant_id=quote(self._tenant))}"

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=req_url, data=urlencode(data), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[DEFENDERATP_TOKEN_STRING] = resp_json
        try:
            self._access_token = resp_json[DEFENDERATP_ACCESS_TOKEN_STRING]
            if DEFENDERATP_REFRESH_TOKEN_STRING in resp_json:
                self._refresh_token = resp_json[DEFENDERATP_REFRESH_TOKEN_STRING]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"Error occurred while generating access token {err}")

        try:
            _save_app_state(self._state, self.get_asset_id(), self)
        except Exception as e:
            self._dump_error_log(e, "Error occurred while parsing the state file.")
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while parsing the state file. Please delete the state file and run the test connectivity again.",
            )

        return phantom.APP_SUCCESS

    def _wait(self, action_result):
        """This function is used to hold the action till user login for 105 seconds.

        :param action_result: Object of ActionResult class
        :return: status (success/failed)
        """

        app_dir = os.path.dirname(os.path.abspath(__file__))
        # file to check whether the request has been granted or not
        auth_status_file_path = f"{app_dir}/{self.get_asset_id()}_{DEFENDERATP_TC_FILE}"
        time_out = False

        # wait-time while request is being granted for 105 seconds
        for _ in range(0, 35):
            self.send_progress("Waiting...")
            self._state = _load_app_state(self.get_asset_id(), self)
            if os.path.isfile(auth_status_file_path):
                time_out = True
                os.unlink(auth_status_file_path)
                break
            time.sleep(DEFENDERATP_TC_STATUS_SLEEP)

        if not time_out:
            self.send_progress("")
            return action_result.set_status(phantom.APP_ERROR, "Timeout. Please try again later")
        self.send_progress("Authenticated")
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """Testing of given credentials and obtaining authorization for all other actions.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(DEFENDERATP_MAKING_CONNECTIVITY_MSG)

        self.save_progress(f"Login URL: {self._login_url}")
        self.save_progress(f"Graph URL: {self._graph_url}")
        self.save_progress(f"Resource URL: {self._resource_url}")

        if not self._state:
            self._state = {}

        if not self._non_interactive:
            # Get initial REST URL
            ret_val, app_rest_url = self._get_app_rest_url(action_result)
            if phantom.is_fail(ret_val):
                self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

            # Append /result to create redirect_uri
            redirect_uri = f"{app_rest_url}/result"
            self._state["redirect_uri"] = redirect_uri

            self.save_progress(DEFENDERATP_OAUTH_URL_MSG)
            self.save_progress(redirect_uri)

            # Authorization URL used to make request for getting code which is used to generate access token
            authorization_url = DEFENDERATP_AUTHORIZE_URL.format(
                tenant_id=quote(self._tenant),
                client_id=quote(self._client_id),
                redirect_uri=redirect_uri,
                state=self.get_asset_id(),
                response_type="code",
                resource=self._resource_url,
            )
            authorization_url = f"{self._login_url}{authorization_url}"

            self._state["authorization_url"] = authorization_url

            # URL which would be shown to the user
            url_for_authorize_request = f"{app_rest_url}/start_oauth?asset_id={self.get_asset_id()}&"
            _save_app_state(self._state, self.get_asset_id(), self)

            self.save_progress(DEFENDERATP_AUTHORIZE_USER_MSG)
            self.save_progress(url_for_authorize_request)  # nosemgrep

            # Wait time for authorization
            time.sleep(DEFENDERATP_AUTHORIZE_WAIT_TIME)

            # Wait for some while user login to Microsoft
            status = self._wait(action_result=action_result)

            # Empty message to override last message of waiting
            self.send_progress("")
            if phantom.is_fail(status):
                self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

            self.save_progress(DEFENDERATP_CODE_RECEIVED_MSG)
            self._state = _load_app_state(self.get_asset_id(), self)

            # if code is not available in the state file
            if not self._state or not self._state.get("code"):
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)

            current_code = self._state["code"]
            try:
                _save_app_state(self._state, self.get_asset_id(), self)
            except Exception as e:
                self._dump_error_log(e, "Error occurred while saving token in state file.")
                return action_result.set_status(
                    phantom.APP_ERROR,
                    status_message="Error occurred while saving token in state file. Please delete the state file and run again.",
                )

        self.save_progress(DEFENDERATP_GENERATING_ACCESS_TOKEN_MSG)

        if not self._non_interactive:
            data = {
                "client_id": self._client_id,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code": current_code,
                "resource": self._resource_url,
                "client_secret": self._client_secret,
            }
        else:
            data = {
                "client_id": self._client_id,
                "grant_type": DEFENDERATP_CLIENT_CREDENTIALS_STRING,
                "client_secret": self._client_secret,
                "resource": self._resource_url,
            }
        # for first time access, new access token is generated
        ret_val = self._generate_new_access_token(action_result=action_result, data=data)

        if phantom.is_fail(ret_val):
            self.send_progress("")
            self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDERATP_ALERTS_INFO_MSG)

        url = f"{self._graph_url}{DEFENDERATP_ALERTS_ENDPOINT}"
        params = {"$top": 1}
        ret_val, response = self._update_request(action_result=action_result, endpoint=url, params=params)
        if phantom.is_fail(ret_val):
            self.send_progress("")
            self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDERATP_RECEIVED_ALERT_INFO_MSG)
        self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_PASSED_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _status_wait(self, action_result, action_id, timeout):
        """This function is used to check status of action on device every 5 seconds for specified timeout period.

        :param action_result: Object of ActionResult class
        :param action_id: ID of the action executed on the device
        :param timeout: timeout period for status check
        :return: status (success/failed), response
        """
        endpoint = f"{self._graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=action_id)}"

        if timeout < 5:
            timeout = 5
        # wait-time while status updates for specified timeout period
        for _ in range(0, int(timeout / 5)):
            # This sleep-time is the time required (0-5 seconds) for the machineaction's command ID details to get reflected
            # on the Defender for Endpoint server. Hence, this sleep-time is explicitly added and added before the first fetch of status.
            time.sleep(DEFENDERATP_STATUS_CHECK_SLEEP)

            # make rest call
            ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            try:
                if response["status"] not in (DEFENDERATP_STATUS_PROGRESS, DEFENDERATP_STATUS_PENDING):
                    return phantom.APP_SUCCESS, response
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return (action_result.set_status(phantom.APP_ERROR, f"Error occurred while processing the response {err}"),)

        return phantom.APP_SUCCESS, response

    def _handle_quarantine_device(self, param):
        """This function is used to handle the quarantine device action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        type = param[DEFENDERATP_JSON_TYPE]
        if type not in TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, f"Please provide valid input from {TYPE_VALUE_LIST} in 'type' action parameter")
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if timeout > DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT

        endpoint = f"{self._graph_url}{DEFENDERATP_ISOLATE_ENDPOINT.format(device_id=device_id)}"

        data = {"Comment": comment, "IsolationType": type}

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get("id"):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary["event_id"] = response["id"]

        action_id = response["id"]
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary["quarantine_status"] = response_status["status"]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):
        """This function is used to handle the unquarantine device action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if timeout > DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT

        endpoint = f"{self._graph_url}{DEFENDERATP_UNISOLATE_ENDPOINT.format(device_id=device_id)}"

        data = {"Comment": comment}

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get("id"):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary["event_id"] = response["id"]

        action_id = response["id"]
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary["unquarantine_status"] = response_status["status"]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_status(self, param):
        """This function is used to handle the get status action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        event_id = param[DEFENDERATP_EVENT_ID]

        endpoint = f"{self._graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=event_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        try:
            summary["event_status"] = response["status"]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"Error occurred while processing the response {err}")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_device_tag(self, param):
        """This function is used to handle the update device tag action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        tag = param[DEFENDERATP_JSON_TAG]
        operation = param[DEFENDERATP_JSON_OPERATION]

        if operation not in TAG_OPERATION_VALUE_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, f"Please provide valid input from {TAG_OPERATION_VALUE_LIST} in 'operation' action parameter"
            )

        endpoint = f"{self._graph_url}{DEFENDERATP_MACHINES_TAGS_ENDPOINT.format(device_id=device_id)}"

        data = {"Action": operation, "Value": tag}

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["tag"] = tag
        summary["operation"] = operation

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_scan_device(self, param):
        """This function is used to handle the scan device action.

        :param param: Dictionary of input parameters
        :return: status(success/failed)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        scan_type = param[DEFENDERATP_JSON_SCAN_TYPE]
        if scan_type not in SCAN_TYPE_VALUE_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, f"Please provide valid input from {SCAN_TYPE_VALUE_LIST} in 'scan_type' action parameter"
            )
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if timeout > DEFENDERATP_SCAN_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_SCAN_TIMEOUT_MAX_LIMIT

        endpoint = DEFENDERATP_SCAN_DEVICE_ENDPOINT.format(device_id=device_id)

        url = f"{self._graph_url}{endpoint}"

        request_data = {"Comment": comment, "ScanType": scan_type}

        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result, method="post", data=json.dumps(request_data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get("id"):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary["event_id"] = response["id"]

        action_id = response["id"]
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary["scan_status"] = response_status["status"]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_file(self, param):
        """This function is used to handle the quarantine file action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        file_hash = param[DEFENDERATP_JSON_FILE_HASH]
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if timeout > DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT

        endpoint = f"{self._graph_url}{DEFENDERATP_FILE_QUARANTINE_ENDPOINT.format(device_id=device_id)}"

        data = {"Comment": comment, "Sha1": file_hash}

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get("id"):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary["event_id"] = response["id"]

        action_id = response["id"]
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary["quarantine_status"] = response_status["status"]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_hash(self, param):
        """This function is used to handle the unblock hash action.

        :param param: Dictionary of input parameters
        :return: status(Success/Failed)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param[DEFENDERATP_JSON_FILE_HASH]
        comment = param[DEFENDERATP_JSON_COMMENT]

        endpoint = f"{self._graph_url}{DEFENDERATP_UNBLOCK_HASH_ENDPOINT.format(file_hash=file_hash)}"

        request_data = {"Comment": comment}

        # make rest call
        ret_val, _ = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(request_data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_FILE_HASH_UNBLOCKED_SUCCESS_MSG)

    def _handle_block_hash(self, param):
        """This function is used to handle the block hash action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param[DEFENDERATP_JSON_FILE_HASH]
        comment = param[DEFENDERATP_JSON_COMMENT]

        endpoint = f"{self._graph_url}{DEFENDERATP_FILE_BLOCK_ENDPOINT.format(file_hash=file_hash)}"

        data = {"Comment": comment}

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_FILE_BLOCKED_MSG)

    def _handle_list_devices(self, param):
        """This function is used to handle the list device action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        input_type = param[DEFENDERATP_JSON_INPUT_TYPE]
        if input_type not in INPUT_TYPE_VALUE_LIST_DEVICES:
            return action_result.set_status(
                phantom.APP_ERROR, f"Please provide valid input from {INPUT_TYPE_VALUE_LIST_DEVICES} in 'input_type' action parameter"
            )

        input = param.get(DEFENDERATP_JSON_INPUT)
        query = param.get(DEFENDERATP_JSON_QUERY, "")

        limit = param.get(DEFENDERATP_JSON_LIMIT, DEFENDERATP_ALERT_DEFAULT_LIMIT)

        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = ""
        # Check if input type is All
        if input_type == DEFENDERATP_ALL_CONST:
            endpoint = DEFENDERATP_MACHINES_ENDPOINT

        # If input not given
        elif input_type and not input:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INPUT_REQUIRED_MSG)

        elif input and input_type:
            # Check for valid domain
            if input_type == DEFENDERATP_DOMAIN_CONST:
                try:
                    if phantom.is_domain(input):
                        endpoint = DEFENDERATP_DOMAIN_MACHINES_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(
                            phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(DEFENDERATP_DOMAIN_CONST)
                        )
                except Exception as e:
                    self._dump_error_log(e, "Error while validating domain.")
                    endpoint = DEFENDERATP_DOMAIN_MACHINES_ENDPOINT.format(input=input)
                    self.error_print(
                        "Validation for the valid domain returned an exception."
                        " Hence, ignoring the validation and continuing the action execution"
                    )

            # Check for valid File hash
            elif input_type == DEFENDERATP_FILE_HASH_CONST:
                try:
                    if phantom.is_sha1(input) or phantom.is_sha256(input) or phantom.is_md5(input):
                        endpoint = DEFENDERATP_FILE_MACHINES_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(
                            phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(DEFENDERATP_FILE_HASH_CONST)
                        )
                except Exception as e:
                    self._dump_error_log(e, "Error occured while validating sha1, sha256, and md5 hash.")
                    endpoint = DEFENDERATP_FILE_MACHINES_ENDPOINT.format(input=input)
                    self.error_print(
                        "Validation for the valid sha1, sha256, and md5 hash returned an exception."
                        " Hence, ignoring the validation and continuing the action execution"
                    )

        url = f"{self._graph_url}{endpoint}?$top={limit}&{query}"

        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_ERROR, "No data found")

        for machine in response.get("value", []):
            action_result.add_data(machine)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_ERROR, "No device found")

        summary = action_result.update_summary({})
        summary["total_devices"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self, param):
        """This function is used to handle the list alerts action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        input_type = param.get(DEFENDERATP_JSON_INPUT_TYPE, DEFENDERATP_ALL_CONST)
        if input_type not in INPUT_TYPE_VALUE_LIST_ALERTS:
            return action_result.set_status(
                phantom.APP_ERROR, f"Please provide valid input from {INPUT_TYPE_VALUE_LIST_ALERTS} in 'input_type' action parameter"
            )

        input = param.get(DEFENDERATP_JSON_INPUT, "")
        limit = param.get(DEFENDERATP_JSON_LIMIT, DEFENDERATP_ALERT_DEFAULT_LIMIT)

        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = ""

        # Check if type is All
        if input_type == DEFENDERATP_ALL_CONST:
            endpoint = DEFENDERATP_ALERTS_ENDPOINT

        # Check if input is not present
        elif input_type and not input:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INPUT_REQUIRED_MSG)

        elif input and input_type:
            # Check for valid IP
            if input_type == DEFENDERATP_IP_CONST:
                try:
                    ipaddress.ip_address(UnicodeDammit(input).unicode_markup)
                except Exception as e:
                    self._dump_error_log(e, "Error occured while validating IP parameter.")
                    return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(DEFENDERATP_IP_CONST))
                endpoint = DEFENDERATP_IP_ALERTS_ENDPOINT.format(input=input)
            # Check for valid domain
            elif input_type == DEFENDERATP_DOMAIN_CONST:
                try:
                    if phantom.is_domain(input):
                        endpoint = DEFENDERATP_DOMAIN_ALERTS_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(
                            phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(DEFENDERATP_DOMAIN_CONST)
                        )
                except Exception as e:
                    self._dump_error_log(e, "Error occured while validating domain parameter.")
                    endpoint = DEFENDERATP_DOMAIN_ALERTS_ENDPOINT.format(input=input)
                    self.error_print(
                        "Validation for the valid domain returned an exception."
                        " Hence, ignoring the validation and continuing the action execution"
                    )

            # Check for valid File hash
            elif input_type == DEFENDERATP_FILE_HASH_CONST:
                try:
                    if phantom.is_sha1(input) or phantom.is_sha256(input) or phantom.is_md5(input):
                        endpoint = DEFENDERATP_FILE_ALERTS_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(
                            phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(DEFENDERATP_FILE_HASH_CONST)
                        )
                except Exception as e:
                    self._dump_error_log(e, "Error occured while validating hash file.")
                    endpoint = DEFENDERATP_FILE_ALERTS_ENDPOINT.format(input=input)
                    self.error_print(
                        "Validation for the valid sha1, sha256, and md5 hash returned an exception."
                        " Hence, ignoring the validation and continuing the action execution"
                    )

        url = f"{self._graph_url}{endpoint}?$top={limit}"

        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_ERROR, "No data found")

        for alert in response.get("value", []):
            action_result.add_data(alert)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_ERROR, "No alerts found")

        summary = action_result.update_summary({})
        summary["total_alerts"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert(self, param):
        """This function is used to handle the get alert action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param[DEFENDERATP_ALERT_ID]

        endpoint = f"{self._graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=alert_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, "No alert found")

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Alert"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_user(self, param):
        """This function is used to handle the get alert user action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param.get("alert_id")

        if not alert_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: alert_id")

        endpoint = f"{self._graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=alert_id)}/user"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Assigned User for Alert"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_files(self, param):
        """This function is used to handle the get alert files action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param.get("alert_id")
        limit = param.get("limit", DEFENDERATP_FILES_DEFAULT_LIMIT)
        offset = param.get("offset", DEFENDERATP_FILES_DEFAULT_OFFSET)

        if not alert_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: alert_id")

        endpoint = f"{self._graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=alert_id)}/files?$top={limit}&$skip={offset}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Files for Alert"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_ips(self, param):
        """This function is used to handle the get alert IPs action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param.get("alert_id")
        limit = param.get("limit", DEFENDERATP_IPS_DEFAULT_LIMIT)
        offset = param.get("offset", DEFENDERATP_IPS_DEFAULT_OFFSET)

        if not alert_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: alert_id")

        endpoint = f"{self._graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=alert_id)}/ips?$top={limit}&$skip={offset}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved IPs for Alert"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_domains(self, param):
        """This function is used to handle the get alert domains action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param.get("alert_id")
        limit = param.get("limit", DEFENDERATP_DOMAINS_DEFAULT_LIMIT)
        offset = param.get("offset", DEFENDERATP_DOMAINS_DEFAULT_OFFSET)

        if not alert_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: alert_id")

        endpoint = f"{self._graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=alert_id)}/domains?$top={limit}&$skip={offset}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Domains for Alert"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_alert(self, param):
        """This function is used to handle the create alert action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        report_id = param.get("report_id")
        event_time = param.get("event_time")
        device_id = param.get("device_id")
        severity = param.get("severity")
        title = param.get("title")
        description = param.get("description")
        recommended_action = param.get("recommended_action")
        category = param.get("category")

        # Validation
        if not all([report_id, event_time, device_id, severity, title, description, recommended_action, category]):
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameters")

        request_body = {
            "reportId": report_id,
            "eventTime": event_time,
            "machineId": device_id,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendedAction": recommended_action,
            "category": category,
        }

        endpoint = f"{self._graph_url}{DEFENDER_CREATE_ALERT_ENDPOINT}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(request_body))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Created Alert"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alert(self, param):
        """This function is used to handle the update alert action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param[DEFENDERATP_ALERT_ID]
        status = param.get(DEFENDERATP_JSON_STATUS)
        assigned_to = param.get(DEFENDERATP_JSON_ASSIGNED_TO)
        classification = param.get(DEFENDERATP_JSON_CLASSIFICATION)
        determination = param.get(DEFENDERATP_JSON_DETERMINATION)
        comment = param.get(DEFENDERATP_JSON_COMMENT)

        request_body = {}

        if status:
            request_body["status"] = status

        if assigned_to:
            request_body["assignedTo"] = assigned_to

        if classification:
            request_body["classification"] = classification

        if determination:
            request_body["determination"] = determination

        if comment:
            request_body["comment"] = comment

        endpoint = f"{self._graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=alert_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="patch", data=json.dumps(request_body))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_NO_DATA_FOUND)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Updated Alert"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user_alerts(self, param):
        """This function retrieves alerts related to a specific user.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        user = param.get("user")

        if not user:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: user")

        endpoint = f"{self._graph_url}{DEFENDER_USER_ALERTS_ENDPOINT.format(user_id=user)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response or not response.get("value", []):
            return action_result.set_status(phantom.APP_SUCCESS, "No alerts found for the specified user")

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Alerts for User"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_domain_alerts(self, param):
        """This function retrieves alerts related to a specific domain address.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param.get("domain")

        if not domain:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: domain")

        endpoint = f"{self._graph_url}{DEFENDER_DOMAIN_ALERTS_ENDPOINT.format(domain=domain)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response or not response.get("value", []):
            return action_result.set_status(phantom.APP_SUCCESS, "No alerts found for the specified domain")

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Alerts for Domain"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file_alerts(self, param):
        """This function retrieves alerts related to a specific file hash.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param.get("file_hash")

        if not file_hash:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: file_hash")

        endpoint = f"{self._graph_url}{DEFENDER_FILE_ALERTS_ENDPOINT.format(file_hash=file_hash)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response or not response.get("value", []):
            return action_result.set_status(phantom.APP_SUCCESS, "No alerts found for the specified file hash")

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Alerts for File"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_alerts(self, param):
        """This function retrieves all alerts related to a specific device using the machineId.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param.get("device_id")

        if not device_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: device_id")

        endpoint = f"{self._graph_url}{DEFENDER_DEVICE_ALERTS_ENDPOINT.format(device_id=device_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response or not response.get("value", []):
            return action_result.set_status(phantom.APP_SUCCESS, "No alerts found for the specified device")

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Alerts for Device"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_active_users(self, param):
        """This function retrieves a collection of logged on users on a specific device by its device ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param.get("device_id")

        if not device_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: device_id")

        endpoint = f"{self._graph_url}{DEFENDER_GET_ACTIVE_DEVICE_USERS.format(device_id=device_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Active Users"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_sessions(self, param):
        """This function is used to handle the list sessions action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        endpoint = f"{self._graph_url}{DEFENDERATP_SESSIONS_ENDPOINT.format(device_id=device_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for session in response.get("value", []):
            action_result.add_data(session)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_ERROR, "No sessions found for the given device")
        summary = action_result.update_summary({})
        summary["total_sessions"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_software(self, param):
        """This function retrieves the organization's software inventory.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        software_id = param.get("id")
        software_name = param.get("name")
        vendor = param.get("vendor")
        limit = param.get("limit", DEFENDERATP_SOFTWARE_DEFAULT_LIMIT)
        offset = param.get("offset", DEFENDERATP_SOFTWARE_DEFAULT_OFFSET)

        ret_val, limit = self._validate_integer(action_result, limit, "limit", allow_zero=False)
        ret_val, offset = self._validate_integer(action_result, offset, "offset", allow_zero=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = f"{DEFENDER_LIST_SOFTWARE_ENDPOINT}?$top={limit}&$skip={offset}"

        if software_id:
            endpoint += f"&id={software_id}"
        if software_name:
            endpoint += f"&name={software_name}"
        if vendor:
            endpoint += f"&vendor={vendor}"

        endpoint = f"{self._graph_url}{endpoint}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        software_list = response.get("value", [])
        for software in software_list:
            action_result.add_data(software)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No software found")

        summary = action_result.update_summary({})
        summary["total_software"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_software_versions(self, param):
        """This function retrieves the software version distribution for a specific software ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        software_id = param.get("id")

        if not software_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: id")

        endpoint = f"{self._graph_url}{DEFENDER_LIST_SOFTWARE_VERSIONS_ENDPOINT.format(software_id=software_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        version_distribution = response.get("value", [])
        for version in version_distribution:
            action_result.add_data(version)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No software versions found for specified software")

        summary = action_result.update_summary({})
        summary["total_versions"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_software_devices(self, param):
        """This function retrieves a list of devices that have a specific software installed by its software ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        software_id = param.get("id")

        if not software_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: id")

        endpoint = f"{self._graph_url}{DEFENDER_LIST_SOFTWARE_DEVICES_ENDPOINT.format(software_id=software_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        devices = response.get("value", [])
        for device in devices:
            action_result.add_data(device)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No devices found for specified software")

        summary = action_result.update_summary({})
        summary["total_devices"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_software_vulnerabilities(self, param):
        """This function retrieves vulnerabilities associated with a specific software by its software ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        software_id = param.get("id")

        if not software_id:
            return action_result.set_status(phantom.APP_SUCCESS, "Missing required parameter: id")

        endpoint = f"{self._graph_url}{DEFENDER_LIST_SOFTWARE_VULNERABILITIES_ENDPOINT.format(software_id=software_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vulnerabilities = response.get("value", [])
        for vulnerability in vulnerabilities:
            action_result.add_data(vulnerability)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No vulnerabilities found for specified software")

        summary = action_result.update_summary({})
        summary["total_vulnerabilities"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_device_vulnerabilities(self, param):
        """This function retrieves vulnerabilities affecting the organization per device or software.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_ids = param.get("device_id")
        software_ids = param.get("software_id")
        cve_ids = param.get("cve_id")
        product_name = param.get("product_name")
        product_version = param.get("product_version")
        severity = param.get("severity")
        product_vendor = param.get("product_vendor")
        limit = param.get("limit", DEFENDERATP_DEVICE_VULNERABILITIES_DEFAULT_LIMIT)
        offset = param.get("offset", DEFENDERATP_DEVICE_VULNERABILITIES_DEFAULT_OFFSET)

        ret_val, limit = self._validate_integer(action_result, limit, "limit", allow_zero=False)
        ret_val, offset = self._validate_integer(action_result, offset, "offset", allow_zero=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = f"{DEFENDER_LIST_DEVICE_VULNERABILITIES_ENDPOINT}?$top={limit}&$skip={offset}"

        filters = []
        if device_ids:
            filters.append(f"machineId eq '{device_ids}'")
        if software_ids:
            filters.append(f"softwareId eq '{software_ids}'")
        if cve_ids:
            filters.append(f"cveId eq '{cve_ids}'")
        if product_name:
            filters.append(f"productName eq '{product_name}'")
        if product_version:
            filters.append(f"productVersion eq '{product_version}'")
        if severity:
            filters.append(f"severity eq '{severity}'")
        if product_vendor:
            filters.append(f"productVendor eq '{product_vendor}'")

        if filters:
            endpoint = "{}&$filter={}".format(endpoint, " and ".join(filters))

        url = f"{self._graph_url}{endpoint}"

        ret_val, response = self._update_request(endpoint=url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vulnerabilities = response.get("value", [])
        for vulnerability in vulnerabilities:
            action_result.add_data(vulnerability)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No vulnerabilities found for specified device")

        summary = action_result.update_summary({})
        summary["total_vulnerabilities"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_vulnerabilities(self, param):
        """This function retrieves a list of vulnerabilities based on filters.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        vulnerability_id = param.get("id")
        name_equal = param.get("name_equal")
        name_contains = param.get("name_contains")
        description_contains = param.get("description_contains")
        published_on = param.get("published_on")
        cvss = param.get("cvss")
        severity = param.get("severity")
        updated_on = param.get("updated_on")
        limit = param.get("limit", DEFENDERATP_VULNERABILITIES_DEFAULT_LIMIT)
        offset = param.get("offset", DEFENDERATP_VULNERABILITIES_DEFAULT_OFFSET)

        ret_val, limit = self._validate_integer(action_result, limit, "limit", allow_zero=False)
        ret_val, offset = self._validate_integer(action_result, offset, "offset", allow_zero=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = f"{DEFENDER_LIST_VULNERABILITIES_ENDPOINT}?$top={limit}&$skip={offset}"

        filters = []
        if vulnerability_id:
            filters.append(f"id eq '{vulnerability_id}'")
        if name_equal:
            filters.append(f"name eq '{name_equal}'")
        if name_contains:
            filters.append(f"contains(name, '{name_contains}')")
        if description_contains:
            filters.append(f"contains(description, '{description_contains}')")
        if published_on:
            filters.append(f"publishedOn eq '{published_on}'")
        if cvss:
            filters.append(f"cvss eq '{cvss}'")
        if severity:
            filters.append(f"severity eq '{severity}'")
        if updated_on:
            filters.append(f"updatedOn eq '{updated_on}'")

        if filters:
            endpoint += "&$filter={}".format(" and ".join(filters))

        endpoint = f"{self._graph_url}{endpoint}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vulnerabilities = response.get("value", [])
        for vulnerability in vulnerabilities:
            action_result.add_data(vulnerability)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No vulnerabilities found")

        summary = action_result.update_summary({})
        summary["total_vulnerabilities"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_prevalence(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_prevalence method")
        return self._handle_prevalence(param, action_identifier)

    def _handle_domain_prevalence(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_prevalence method")
        return self._handle_prevalence(param, action_identifier)

    def _handle_file_prevalence(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_prevalence method")
        return self._handle_prevalence(param, action_identifier)

    def _handle_prevalence(self, param, action_identifier):
        """This function is used to handle the IP, Domain & File Prevalence action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {action_identifier}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        if action_identifier == "ip_prevalence":
            ip_input = param[DEFENDERATP_IP_PARAM_CONST]
            endpoint = DEFENDERATP_IP_PREVALENCE_ENDPOINT.format(ip=ip_input)
        elif action_identifier == "domain_prevalence":
            domain_input = param[DEFENDERATP_DOMAIN_PARAM_CONST]
            endpoint = DEFENDERATP_DOMAIN_PREVALENCE_ENDPOINT.format(domain=domain_input)
        else:
            file_input = param[DEFENDERATP_FILE_PARAM_CONST]
            endpoint = DEFENDERATP_FILE_PREVALENCE_ENDPOINT.format(id=file_input)

        # lookBackHours
        look_back_hours = param.get(DEFENDERATP_LOOK_BACK_HOURS_PARAM_CONST, DEFENDERATP_MAX_LOOK_BACK_HOURS)

        # Check for integer value
        ret_val, look_back_hours = self._validate_integer(action_result, look_back_hours, LOOK_BACK_HOURS_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Upper limit validation for look_back_hours
        if look_back_hours > DEFENDERATP_MAX_LOOK_BACK_HOURS:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_LOOK_BACK_HOURS)

        # URL
        url = f"{self._graph_url}{endpoint}"

        # Prepare request params
        params = {"lookBackHours": look_back_hours}
        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_NO_DATA_FOUND)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["organization_prevalence"] = response.get("organizationPrevalence", 0)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file_info(self, param):
        """This function is used to handle the get file info action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param[DEFENDERATP_JSON_FILE_HASH]
        endpoint = f"{self._graph_url}{DEFENDERATP_FILE_INFO_ENDPOINT.format(file_hash=file_hash)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_NO_DATA_FOUND)
        else:
            action_result.add_data(response)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_NO_DATA_FOUND)

        summary = action_result.update_summary({})
        summary["global_prevalence"] = response.get("globalPrevalence", 0)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved file information")

    def _handle_get_domain_related_devices(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_get_related_devices method")
        return self._handle_get_related_devices(param, action_identifier)

    def _handle_get_file_related_devices(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_get_related_devices method")
        return self._handle_get_related_devices(param, action_identifier)

    def _handle_get_user_related_devices(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_get_related_devices method")
        return self._handle_get_related_devices(param, action_identifier)

    def _handle_get_related_devices(self, param, action_identifier):
        """This function is used to handle the get file related devices, get user related devices and get domain related devices action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        if action_identifier == "get_file_related_devices":
            file_hash = param[DEFENDERATP_JSON_FILE_HASH]
            endpoint = f"{self._graph_url}{DEFENDERATP_MACHINE_FILES_ENDPOINT.format(file_hash=file_hash)}"

        elif action_identifier == "get_domain_related_devices":
            domain = param[DEFENDERATP_DOMAIN_PARAM_CONST]
            endpoint = f"{self._graph_url}{DEFENDERATP_DOMAIN_MACHINES_ENDPOINT.format(input=domain)}"

        elif action_identifier == "get_user_related_devices":
            user_id = param[DEFENDERATP_JSON_USER_ID]
            endpoint = f"{self._graph_url}{DEFENDERATP_USER_FILES_ENDPOINT.format(file_hash=user_id)}"

        else:
            return action_result.set_status(phantom.APP_ERROR, "Action identifier did not match")

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for device in response.get("value", []):
            action_result.add_data(device)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No devices found")

        summary = action_result.update_summary({})
        summary["total_devices"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_installed_software(self, param):
        """This function is used to handle the get installed software action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        endpoint = f"{self._graph_url}{DEFENDERATP_INSTALLED_SOFTWARE_ENDPOINT.format(device_id=device_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for software in response.get("value", []):
            action_result.add_data(software)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No software found for the given device")

        summary = action_result.update_summary({})
        summary["total_software"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restrict_app_execution(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_app_execution method")
        return self._handle_app_execution(param, action_identifier)

    def _handle_remove_app_restriction(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_app_execution method")
        return self._handle_app_execution(param, action_identifier)

    def _handle_app_execution(self, param, action_identifier):
        """This function is used to handle the restrict app execution and remove app restriction action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if timeout > DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT

        if action_identifier == "restrict_app_execution":
            endpoint = f"{self._graph_url}{DEFENDERATP_RESTRICT_APP_EXECUTION_ENDPOINT.format(device_id=device_id)}"
            app_restriction_summary = "restrict_app_execution_status"

        elif action_identifier == "remove_app_restriction":
            endpoint = f"{self._graph_url}{DEFENDERATP_REMOVE_APP_RESTRICTION_ENDPOINT.format(device_id=device_id)}"
            app_restriction_summary = "remove_app_restriction_status"

        else:
            return action_result.set_status(phantom.APP_ERROR, "Action identifier did not match")

        data = {"Comment": comment}

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get("id"):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary["event_id"] = response["id"]

        action_id = response["id"]
        # Wait till the status of the action gets updated
        status, response_status = self._status_wait(action_result, action_id, timeout)

        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary[app_restriction_summary] = response_status.get("status")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_collect_investigation_package(self, param):
        """This function collects an investigation package from a device by its device ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param.get("device_id")
        comment = param.get("comment")

        if not device_id or not comment:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameters")

        endpoint = f"{self._graph_url}{DEFENDER_COLLECT_INVESTIGATION_PACKAGE_ENDPOINT.format(device_id=device_id)}"

        payload = {"Comment": comment}

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(payload))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Collected Investigation Package"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_investigation_uri(self, param):
        """This function retrieves a URI for downloading an investigation package by its action ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_id = param.get("action_id")

        if not action_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: action_id")

        endpoint = f"{self._graph_url}{DEFENDER_GET_INVESTIGATION_URI.format(action_id=action_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Investigation URI"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_details(self, param):
        """This function retrieves details for multiple devices by their device IDs.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_ids = param.get("device_ids")

        if not device_ids:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: device_ids")

        device_id_list = [device_id.strip() for device_id in device_ids.split(",") if device_id.strip()]

        all_device_details = []
        for device_id in device_id_list:
            endpoint = f"{self._graph_url}{DEFENDER_DEVICE_DETAILS_ENDPOINT.format(device_id=device_id)}"

            ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if response:
                action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Device Details"
        summary["total_results"] = len(all_device_details)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_affected_devices(self, param):
        """This function retrieves a list of devices affected by a vulnerability using CVE IDs.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        cve_id = param.get("cve_id")

        if not cve_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: cve_id")

        endpoint = f"{self._graph_url}{DEFENDER_GET_VULNERABILITY_AFFECTED_DEVICES_ENDPOINT.format(cve_id=cve_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Affected Devices"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_indicator(self, param):
        """This function is used to retrieve an indicator by its ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator_id = param.get("indicator_id")

        if not indicator_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: indicator_id")

        endpoint = f"{self._graph_url}{DEFENDER_GET_INDICATOR_ENDPOINT.format(indicator_id=indicator_id)}"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Retrieved Indicator"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_indicators(self, param):
        """This function is used to handle the list indicators action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get(DEFENDERATP_JSON_LIMIT, DEFENDERATP_ALERT_DEFAULT_LIMIT)

        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY, allow_zero=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = f"{DEFENDERATP_LIST_INDICATORS_ENDPOINT}?$top={limit}"

        filter = param.get(DEFENDERATP_JSON_FILTER)
        if filter:
            endpoint = "{}&$filter={}".format(endpoint, filter.replace("&", "%26"))

        url = f"{self._graph_url}{endpoint}"

        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_NO_DATA_FOUND)

        indicators = response.get("value", [])
        len_indicators = len(indicators)

        for indicator in indicators:
            action_result.add_data(indicator)

        summary = action_result.update_summary({})
        summary["total_indicators"] = len_indicators

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_indicator(self, param):
        """This function is used to update an indicator.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator_value = param.get("indicator_value")
        indicator_type = param.get("indicator_type")
        action_taken = param.get("action")
        description = param.get("indicator_description")
        title = param.get("indicator_title")

        if not all([indicator_value, indicator_type, action_taken, description, title]):
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameters")

        endpoint = f"{self._graph_url}{DEFENDER_UPDATE_INDICATOR_ENDPOINT}"

        payload = {
            "indicatorValue": indicator_value,
            "indicatorType": indicator_type,
            "action": action_taken,
            "description": description,
            "title": title,
        }

        severity = param.get("severity")
        if severity:
            payload["severity"] = severity

        expiration_time = param.get("expiration_time")
        if expiration_time:
            payload["expirationTime"] = expiration_time

        indicator_application = param.get("indicator_application")
        if indicator_application:
            payload["application"] = indicator_application

        recommended_actions = param.get("recommended_actions")
        if recommended_actions:
            payload["recommendedActions"] = recommended_actions

        rbac_group_names = param.get("rbac_group_names")
        if rbac_group_names:
            payload["rbacGroupNames"] = rbac_group_names

        payload = {"Indicators": [payload]}

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, data=json.dumps(payload), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for obj in response.get("value", []):
            action_result.add_data(obj)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Updated Indicator"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_indicator_batch(self, param):
        """This function is used to update a batch of indicators

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator_batch = param.get("indicator_batch")

        if not indicator_batch:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: indicator_batch")

        try:
            indicator_batch = json.loads(indicator_batch)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Error processing batch: {e!s}")

        if not isinstance(indicator_batch, list):
            return action_result.set_status(phantom.APP_ERROR, "indicator_batch must be a list of dictionaries")

        endpoint = f"{self._graph_url}{DEFENDER_UPDATE_INDICATOR_ENDPOINT}"

        payload = {"Indicators": indicator_batch}

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, data=json.dumps(payload), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for obj in response.get("value", []):
            action_result.add_data(obj)

        # Update the summary and return success
        summary = action_result.update_summary({})
        summary["action_taken"] = "Updated batch of indicators"
        summary["total_results"] = len(response.get("value", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_indicator(self, param):
        """This function is used to handle the delete indicator action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator_id = param[DEFENDERATP_JSON_INDICATOR_ID]
        endpoint = f"{self._graph_url}{DEFENDERATP_LIST_INDICATORS_ENDPOINT}/{indicator_id}"

        # make rest call
        ret_val, _ = self._update_request(endpoint=endpoint, action_result=action_result, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted indicator entity")

    def _check_expiration_time_format(self, action_result, date):
        """Validate the value of expiration time parameter given in the action parameters.

        Parameters:
            :param date: value of expiration time action parameter
        Returns:
            :return: status(True/False), time
        """
        # Initialize time for given value of date
        time = None
        try:
            # Check for the time is in valid format or not
            time = datetime.strptime(date, DEFENDERATP_DATE_FORMAT)
        except Exception as e:
            self._dump_error_log(e, "Error occured while  checking date format")
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_TIME_ERR.format("expiration time")), None

        # Checking for future date
        try:
            # Try Python 3.11+ approach
            today = datetime.now(datetime.UTC)
        except AttributeError as e:
            # Fall back to Python 3.9 approach
            self.debug_print(f"Got AttributeError. Exception: {e}")
            self.debug_print("Falling back to Python 3.9 approach")
            today = datetime.now(timezone.utc)

            # Make time timezone-aware before comparison
            time = time.replace(tzinfo=timezone.utc)
            self.debug_print(f"Time after changing timezone-aware: {time}")

        if time <= today:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_PAST_TIME_ERR.format("expiration time")), None

        time = time.strftime(DEFENDERATP_DATE_FORMAT)

        return phantom.APP_SUCCESS, time

    def _handle_submit_indicator(self, param):
        """This function is used to handle the submit indicator action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        title = param[DEFENDERATP_JSON_INDICATOR_TITLE]
        description = param[DEFENDERATP_JSON_INDICATOR_DESCRIPTION]
        indicator_value = param[DEFENDERATP_JSON_INDICATOR_VALUE]

        # 'indicator_type' input parameter
        indicator_type = param[DEFENDERATP_JSON_INDICATOR_TYPE]

        # 'action' input parameter
        action = param[DEFENDERATP_JSON_ACTION]

        application = param.get(DEFENDERATP_JSON_APPLICATION)
        recommended_actions = param.get(DEFENDERATP_JSON_RECOMMENDED_ACTIONS)

        generate_alert = param.get(DEFENDERATP_JSON_GENERATE_ALERT, False)

        expiration_time = param.get(DEFENDERATP_JSON_EXPIRATION_TIME)
        # Checking date format
        if expiration_time:
            ret_val, expiration_time = self._check_expiration_time_format(action_result, expiration_time)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        rbac_group_names_list = None
        rbac_group_names = param.get(DEFENDERATP_JSON_RBAC_GROUP_NAMES)
        if rbac_group_names:
            # Load the json value
            try:
                rbac_group_names_list = json.loads(rbac_group_names)
                # Check for valid JSON formatted list
                if not isinstance(rbac_group_names_list, list):
                    return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_LIST_JSON_ERR.format("rbac_group_names"))
            except Exception as e:
                self._dump_error_log(e, "Error occured while checking rbac_group_names")
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_LIST_JSON_ERR.format("rbac_group_names"))
            # Remove empty values from the list
            rbac_group_names_list = list(filter(None, rbac_group_names_list))
            if not rbac_group_names_list:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_RBAC_GROUP_NAMES)

        severity = param.get(DEFENDERATP_JSON_SEVERITY)
        if severity and severity not in INDICATOR_SEVERITY_LIST:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_SEVERITY)

        # prepare data parameters
        data = {
            "indicatorValue": indicator_value,
            "indicatorType": indicator_type,
            "title": title,
            "action": action,
            "description": description,
            "generateAlert": generate_alert,
        }

        if application:
            data.update({"application": application})

        if expiration_time:
            data.update({"expirationTime": expiration_time})

        if recommended_actions:
            data.update({"recommendedActions": recommended_actions})

        if rbac_group_names:
            data.update({"rbacGroupNames": rbac_group_names_list})

        if severity:
            data.update({"severity": severity})

        endpoint = f"{self._graph_url}{DEFENDERATP_LIST_INDICATORS_ENDPOINT}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, data=json.dumps(data), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_SUBMIT_INDICATOR_PARSE_ERR)

        indicator_id = response.get("id")
        if not indicator_id:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_SUBMIT_INDICATOR_ID_PARSE_ERR)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["indicator_id"] = indicator_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):
        """This function is used to handle the run query action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param[DEFENDERATP_JSON_QUERY]

        # prepare data parameters
        data = {"Query": query}

        endpoint = f"{self._graph_url}{DEFENDERATP_RUN_QUERY_ENDPOINT}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, data=json.dumps(data), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_NO_DATA_FOUND)

        results = response.get("Results", [])
        len_results = len(results)

        for result in results:
            action_result.add_data(result)

        summary = action_result.update_summary({})
        summary["total_results"] = len_results

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_discovered_vulnerabilities(self, param):
        """This function is used to handle the get doscovered vulnerabilities action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        endpoint = f"{self._graph_url}{DEFENDERATP_VULNERABILITIES_ENDPOINT.format(device_id=device_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for vulnerability in response.get("value", []):
            action_result.add_data(vulnerability)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No vulnerabilities found for the given device")

        summary = action_result.update_summary({})
        summary["total_vulnerabilities"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_exposure_score(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_get_score method")
        return self._handle_get_score(param, action_identifier)

    def _handle_get_secure_score(self, param):
        action_identifier = self.get_action_identifier()
        self.save_progress(f"In action handler for {action_identifier}")
        self.debug_print("Calling _handle_get_score method")
        return self._handle_get_score(param, action_identifier)

    def _handle_get_score(self, param, action_identifier):
        """This function is used to handle the get exposure score and get secure score action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for {action_identifier}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = ""
        action_score_summary_key = ""

        if action_identifier == "get_exposure_score":
            endpoint = f"{self._graph_url}{DEFENDERATP_EXPOSURE_ENDPOINT}"
            action_score_summary_key = "exposure_score"

        elif action_identifier == "get_secure_score":
            endpoint = f"{self._graph_url}{DEFENDERATP_SECURE_ENDPOINT}"
            action_score_summary_key = "secure_score"

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response and response.get("score"):
            action_result.add_data(response)
        else:
            return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_NO_DATA_FOUND)

        summary = action_result.update_summary({})
        summary[action_score_summary_key] = response.get("score")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _vault_file(self, filename=None, content=None):
        if not filename or not content:
            return "Error: one or more arguments are null value", None

        gzip_filename = f"{filename}.gz"
        guid = uuid.uuid4()

        if hasattr(Vault, "get_vault_tmp_dir"):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = "/vault/tmp"

        local_dir = f"{temp_dir}/{guid}"
        self.save_progress(f"Using temp directory: {guid}")

        try:
            os.makedirs(local_dir)
        except Exception as e:
            self._dump_error_log(e, "Error occured while creating directory.")
            return "Error while creating directory", None

        gzip_file_path = f"{local_dir}/{gzip_filename}"
        file_path = f"{local_dir}/{filename}"

        # For image files add the content in .gz file
        with open(gzip_file_path, "wb") as f:
            f.write(content)

        try:
            # Extracting .gz file
            with gzip.open(gzip_file_path, "rb") as f_in, open(file_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        except Exception as e:
            self._dump_error_log(e, "Error occured while extracting .gz file.")
            # For other type of files add the content in the actual file
            with open(file_path, "wb") as f_out:
                f_out.write(content)

        try:
            # Adding file to vault
            success, _, vault_id = ph_rules.vault_add(file_location=file_path, container=self.get_container_id(), file_name=filename)
        except Exception as e:
            self._dump_error_log(e, "Error occured while adding the file to vault")
            return "Error: Unable to add the file to vault", None

        if not success:
            return "Error: Unable to add the file to vault", None

        return True, vault_id

    def _get_live_response_result(self, action_id, action_result):
        endpoint = f"{self._graph_url}{DEFENDERATP_LIVE_RESPONSE_RESULT_ENDPOINT.format(action_id=action_id)}"
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        if response.get("value"):
            response = requests.get(response["value"])  # nosemgrep: python.requests.best-practice.use-timeout.use-timeout
            if response.status_code == 200:
                return action_result.set_status(phantom.APP_SUCCESS), response

        return action_result.set_status(phantom.APP_ERROR, "No result found for live response action"), None

    def _validate_event_id(self, event_id, command, action_result, summary):
        endpoint = f"{self._graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=event_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            summary["event_id_status"] = action_result.get_message()
            summary["event_id"] = event_id
            event_id = None
            return phantom.APP_SUCCESS, event_id, None
        else:
            status = response.get("status")
            commands = response.get("commands")
            summary["event_id_status"] = status
            summary["event_id"] = event_id
            try:
                command_type = commands[0].get("command", {}).get("type")
                if not command_type or command_type != command:
                    return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_COMMAND_ERR.format(command)), event_id, None
            except Exception as e:
                self._dump_error_log(e, "Error occured while getting command type.")
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_COMMAND_ERR.format(command)), event_id, None
            if status == DEFENDERATP_STATUS_FAILED:
                event_id = None
                return phantom.APP_SUCCESS, event_id, None
            if status != DEFENDERATP_STATUS_SUCCESS:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INVALID_EVENT_ID_ERR.format(status)), event_id, None
            return action_result.set_status(phantom.APP_SUCCESS), event_id, response

    def _handle_get_file_live_response(self, param):
        """This function is used to handle the get file action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        event_id = param.get(DEFENDERATP_EVENT_ID)
        file_path = param.get(DEFENDERATP_JSON_FILE_PATH)
        device_id = param.get(DEFENDERATP_JSON_DEVICE_ID)
        comment = param.get(DEFENDERATP_JSON_COMMENT)

        required_params = file_path and device_id and comment
        if not (event_id or required_params):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_REQUIRED_PARAMETER_ERR.format(DEFENDERATP_JSON_FILE_PATH))

        if event_id:
            ret_val, event_id, response = self._validate_event_id(event_id, DEFENDERATP_GET_FILE_COMMAND, action_result, summary)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            if response:
                action_result.add_data(response)

        # the event_id is updated hence checking it
        if not event_id:
            if not required_params:
                return action_result.set_status(phantom.APP_ERROR)
            timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_LIVE_RESPONSE_DEFAULT)

            ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY)
            if phantom.is_fail(ret_val):
                summary["file_status"] = action_result.get_message()
                return action_result.set_status(phantom.APP_ERROR)

            endpoint = f"{self._graph_url}{DEFENDERATP_LIVE_RESPONSE_ENDPOINT.format(device_id=device_id)}"

            data = {"Comment": comment, "Commands": [{"type": DEFENDERATP_GET_FILE_COMMAND, "params": [{"key": "Path", "value": file_path}]}]}

            # make rest call
            ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

            if phantom.is_fail(ret_val):
                summary["file_status"] = action_result.get_message()
                return action_result.set_status(phantom.APP_ERROR)

            if not response.get("id"):
                summary["file_status"] = DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG
                return action_result.set_status(phantom.APP_ERROR)

            event_id = response["id"]

            # Wait till the status of the action gets updated
            status, response = self._status_wait(action_result, event_id, timeout)

            if phantom.is_fail(status):
                summary["file_status"] = action_result.get_message()
                return action_result.set_status(phantom.APP_ERROR)

            action_result.add_data(response)
            status = response.get("status")

            self.debug_print(f"Status of live response action: {status}")
            self.debug_print("Command Status of live response action: {}".format(response.get("commands")))

            summary["file_status"] = status
            summary["event_id"] = event_id
            if status != DEFENDERATP_STATUS_SUCCESS:
                if status == DEFENDERATP_STATUS_FAILED:
                    return action_result.set_status(phantom.APP_ERROR)
                return action_result.set_status(phantom.APP_SUCCESS)

        # getting live response result
        ret_val, result = self._get_live_response_result(event_id, action_result)

        if phantom.is_fail(ret_val):
            summary["live_response_result"] = action_result.get_message()
            return action_result.set_status(phantom.APP_ERROR)

        if not result:
            summary["live_response_result"] = DEFENDERATP_NO_DATA_FOUND
            return action_result.set_status(phantom.APP_ERROR)

        try:
            file_name = result.headers.get("Content-Disposition")
            file_name = unquote(str(re.findall("filename=(.+)", file_name)[0]).strip('"').rsplit(".gz", 1)[0])
        except Exception as e:
            self._dump_error_log(e, "Error occured while finding filename from header.")
            summary["live_response_result"] = "Error occurred while getting the file name"
            return action_result.set_status(phantom.APP_ERROR)

        ret_val, vault_id = self._vault_file(filename=file_name, content=result.content)

        if ret_val is not True:
            summary["live_response_result"] = "Error occurred while adding file to vault"
            return action_result.set_status(phantom.APP_ERROR)

        # Adding vault ID to summary
        summary["vault_id"] = vault_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_put_file_live_response(self, param):
        """This function is used to handle the put file action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_name = param[DEFENDERATP_JSON_FILE_NAME]
        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        comment = param[DEFENDERATP_JSON_COMMENT]

        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_LIVE_RESPONSE_DEFAULT)

        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = f"{self._graph_url}{DEFENDERATP_LIVE_RESPONSE_ENDPOINT.format(device_id=device_id)}"

        data = {"Comment": comment, "Commands": [{"type": DEFENDERATP_PUT_FILE_COMMAND, "params": [{"key": "FileName", "value": file_name}]}]}

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get("id"):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        action_id = response["id"]
        summary = action_result.update_summary({})
        summary["event_id"] = action_id

        # Wait till the status of the action gets updated
        status, response = self._status_wait(action_result, action_id, timeout)

        status = response.get("status")
        self.debug_print(f"Status of live response action: {status}")
        self.debug_print("Command Status of live response action: {}".format(response.get("commands")))

        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["put_file_status"] = status

        if status == DEFENDERATP_STATUS_FAILED:
            return action_result.set_status(phantom.APP_ERROR)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_cancel_live_response(self, param):
        """This function cancels a live response action with an unfinished status.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_id = param.get("action_id")
        comment = param.get("comment")

        if not action_id or not comment:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameters")

        endpoint = f"{self._graph_url}{DEFENDER_LIVE_RESPONSE_CANCEL_ENDPOINT.format(action_id=action_id)}"

        payload = {"Comment": comment}

        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(payload))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["action_taken"] = "Canceled Live Response Action"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_script_live_response(self, param):
        """This function is used to handle the run script action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        event_id = param.get(DEFENDERATP_EVENT_ID)
        script_name = param.get(DEFENDERATP_JSON_SCRIPT_NAME)
        device_id = param.get(DEFENDERATP_JSON_DEVICE_ID)
        comment = param.get(DEFENDERATP_JSON_COMMENT)

        required_params = script_name and device_id and comment
        if not (event_id or required_params):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_REQUIRED_PARAMETER_ERR.format(DEFENDERATP_JSON_SCRIPT_NAME))

        if event_id:
            ret_val, event_id, response = self._validate_event_id(event_id, DEFENDERATP_RUN_SCRIPT_COMMAND, action_result, summary)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        if not event_id:
            if not required_params:
                return action_result.set_status(phantom.APP_ERROR)
            timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_LIVE_RESPONSE_DEFAULT)
            script_args = param.get(DEFENDERATP_JSON_SCRIPT_ARGS)

            ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_KEY)
            if phantom.is_fail(ret_val):
                summary["script_status"] = action_result.get_message()
                return action_result.set_status(phantom.APP_ERROR)

            if timeout > DEFENDERATP_RUN_SCRIPT_MAX_LIMIT:
                timeout = DEFENDERATP_RUN_SCRIPT_MAX_LIMIT

            endpoint = f"{self._graph_url}{DEFENDERATP_LIVE_RESPONSE_ENDPOINT.format(device_id=device_id)}"

            data = {
                "Comment": comment,
                "Commands": [{"type": DEFENDERATP_RUN_SCRIPT_COMMAND, "params": [{"key": "ScriptName", "value": script_name}]}],
            }
            if script_args:
                data["Commands"][0]["params"].append({"key": "Args", "value": script_args})

            # make rest call
            ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method="post", data=json.dumps(data))

            if phantom.is_fail(ret_val):
                summary["script_status"] = action_result.get_message()
                return action_result.set_status(phantom.APP_ERROR)

            if not response.get("id"):
                summary["script_status"] = DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG
                return action_result.set_status(phantom.APP_ERROR)

            event_id = response["id"]
            # Wait till the status of the action gets updated
            status, response = self._status_wait(action_result, event_id, timeout)

            if phantom.is_fail(status):
                summary["script_status"] = action_result.get_message()
                summary["event_id"] = event_id
                return action_result.set_status(phantom.APP_ERROR)

            status = response.get("status")
            self.debug_print(f"Status of live response action: {status}")
            self.debug_print("Command Status of live response action: {}".format(response.get("commands")))

            summary["script_status"] = status
            summary["event_id"] = event_id
            if status != DEFENDERATP_STATUS_SUCCESS:
                if status == DEFENDERATP_STATUS_FAILED:
                    return action_result.set_status(phantom.APP_ERROR)
                return action_result.set_status(phantom.APP_SUCCESS)

        # getting live response result
        ret_val, result = self._get_live_response_result(event_id, action_result)

        if phantom.is_fail(ret_val):
            summary["live_response_result"] = action_result.get_message()
            return action_result.set_status(phantom.APP_ERROR)

        if not result:
            summary["live_response_result"] = DEFENDERATP_NO_DATA_FOUND
            return action_result.set_status(phantom.APP_ERROR)

        try:
            # Process a json response
            resp_json = result.json()
            resp_json = self.replace_null_values(resp_json)
        except Exception as e:
            summary["live_response_result"] = f"Unable to parse JSON response. Error: {self._get_error_message_from_exception(e)}"
            return action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_missing_kbs(self, param):
        """This function is used to handle the get missing KBs action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        endpoint = f"{self._graph_url}{DEFENDERATP_MISSING_KBS_ENDPOINT.format(device_id=device_id)}"

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for kb in response.get("value", []):
            action_result.add_data(kb)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_SUCCESS, "No missing KBs found for the given device")

        summary = action_result.update_summary({})
        summary["total_kbs"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        """This function ingests Microsoft Defender for Endpoint alerts during scheduled or manual polling.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        config = self.get_config()

        poll_filter = config.get(DEFENDER_FILTER, "")
        last_modified_time = (datetime.now() - timedelta(days=DEFENDER_ALERT_DEFAULT_TIME_RANGE)).strftime(DEFENDER_APP_DT_STR_FORMAT)

        start_time_scheduled_poll = config.get(DEFENDER_CONFIG_START_TIME_SCHEDULED_POLL)
        if start_time_scheduled_poll:
            ret_val = self._check_date_format(action_result, start_time_scheduled_poll)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            last_modified_time = start_time_scheduled_poll

        if self.is_poll_now():
            max_alerts = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))
        else:
            max_alerts = config.get(DEFENDER_CONFIG_FIRST_RUN_MAX_ALERTS, DEFENDER_ALERT_DEFAULT_LIMIT_FOR_SCHEDULE_POLLING)
            ret_val, max_alerts = self._validate_integer(action_result, max_alerts, "max_alerts")
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        # Pick up from last ingested alerts if applicable
        if self._state.get(STATE_FIRST_RUN, True):
            self._state[STATE_FIRST_RUN] = False
        elif last_time := self._state.get(STATE_LAST_TIME):
            last_modified_time = last_time

        start_time_filter = f"lastUpdateTime ge {last_modified_time}"
        poll_filter += start_time_filter if not poll_filter else f" and {start_time_filter}"

        endpoint = f"{self._graph_url}{DEFENDERATP_ALERTS_ENDPOINT}?$top={max_alerts}&$filter={poll_filter}"
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        alert_list = response.get("value", [])

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(f"Successfully fetched {len(alert_list)} alerts.")
        for alert in alert_list:
            try:
                # Ingest alert
                ret_val = self._ingest_alert(action_result, alert)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"Could not ingested alert. Error: {e}")

            # Set state to last modified time of last alert so we can pick up from there next time
            self._state[STATE_LAST_TIME] = alert_list[-1].get(DEFENDER_JSON_LAST_MODIFIED)
            self.save_state(deepcopy(self._state))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _ingest_alert(self, action_result, alert):
        """This helper function ingests a single alert as a container with its artifacts.

        :param alert: Dictionary containing alert details
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        acceptable_severities = ["low", "medium", "high"]

        alert_severity = alert.get("severity").lower()

        severity = alert_severity if alert_severity in acceptable_severities else "low"

        artifact = {
            "label": "alert",
            "name": alert.get("title"),
            "source_data_identifier": alert.get("id"),
            "severity": severity,
            "data": alert,
            "cef": alert,
        }

        container = {
            "name": alert.get("title"),
            "description": "Alert ingested using MS Defender for Endpoint",
            "source_data_identifier": alert.get("id"),
            "severity": severity,
        }

        ret_val, message, cid = self.save_container(container)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, message)

        self.debug_print(f"save_container returned: {ret_val}, reason: {message}, id: {cid}")

        if message in "Duplicate container found":
            self.save_progress("Duplicate container found. Continuing with the same container.")

        artifact["container_id"] = cid
        ret_val, message, _ = self.save_artifacts([artifact])

        return phantom.APP_SUCCESS

    def _check_date_format(self, action_result, date):
        """This helper function is used to check date format.

        :param action_result: action result object
        :param date: date string
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), date
        """

        try:
            time = datetime.strptime(date, DEFENDER_APP_DT_STR_FORMAT)
            try:
                # Try Python 3.11+ approach
                end_time = datetime.now(datetime.UTC)
            except AttributeError:
                # Fall back to Python 3.9 approach
                end_time = datetime.now(timezone.utc)
                # Make time timezone-aware before comparison
                time = time.replace(tzinfo=timezone.utc)

            if time >= end_time:
                message = LOG_GREATER_EQUAL_TIME_ERR.format(LOG_CONFIG_TIME_POLL_NOW)
                return action_result.set_status(phantom.APP_ERROR, message)
        except Exception as e:
            message = f"Invalid date string received. Error occurred while checking date format. Error: {e!s}"
            return action_result.set_status(phantom.APP_ERROR, message)

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "on_poll": self._handle_on_poll,
            "quarantine_device": self._handle_quarantine_device,
            "unquarantine_device": self._handle_unquarantine_device,
            "get_status": self._handle_get_status,
            "scan_device": self._handle_scan_device,
            "quarantine_file": self._handle_quarantine_file,
            "list_devices": self._handle_list_devices,
            "list_alerts": self._handle_list_alerts,
            "list_sessions": self._handle_list_sessions,
            "list_software": self._handle_list_software,
            "list_software_versions": self._handle_list_software_versions,
            "list_software_devices": self._handle_list_software_devices,
            "list_software_vulnerabilities": self._handle_list_software_vulnerabilities,
            "list_device_vulnerabilities": self._handle_list_device_vulnerabilities,
            "list_vulnerabilities": self._handle_list_vulnerabilities,
            "get_alert": self._handle_get_alert,
            "get_alert_user": self._handle_get_alert_user,
            "get_alert_files": self._handle_get_alert_files,
            "get_alert_ips": self._handle_get_alert_ips,
            "get_alert_domains": self._handle_get_alert_domains,
            "create_alert": self._handle_create_alert,
            "update_alert": self._handle_update_alert,
            "get_user_alerts": self._handle_get_user_alerts,
            "get_domain_alerts": self._handle_get_domain_alerts,
            "get_file_alerts": self._handle_get_file_alerts,
            "get_device_alerts": self._handle_get_device_alerts,
            "ip_prevalence": self._handle_ip_prevalence,
            "domain_prevalence": self._handle_domain_prevalence,
            "file_prevalence": self._handle_file_prevalence,
            "get_file_info": self._handle_get_file_info,
            "get_file_related_devices": self._handle_get_file_related_devices,
            "get_user_related_devices": self._handle_get_user_related_devices,
            "get_installed_software": self._handle_get_installed_software,
            "restrict_app_execution": self._handle_restrict_app_execution,
            "remove_app_restriction": self._handle_remove_app_restriction,
            "collect_investigation_package": self._handle_collect_investigation_package,
            "get_investigation_uri": self._handle_get_investigation_uri,
            "get_device_details": self._handle_get_device_details,
            "get_active_users": self._handle_get_active_users,
            "get_affected_devices": self._handle_get_affected_devices,
            "get_indicator": self._handle_get_indicator,
            "list_indicators": self._handle_list_indicators,
            "delete_indicator": self._handle_delete_indicator,
            "submit_indicator": self._handle_submit_indicator,
            "update_indicator": self._handle_update_indicator,
            "update_indicator_batch": self._handle_update_indicator_batch,
            "run_query": self._handle_run_query,
            "get_domain_related_devices": self._handle_get_domain_related_devices,
            "get_discovered_vulnerabilities": self._get_discovered_vulnerabilities,
            "get_exposure_score": self._handle_get_exposure_score,
            "get_secure_score": self._handle_get_secure_score,
            "get_file_live_response": self._handle_get_file_live_response,
            "put_file_live_response": self._handle_put_file_live_response,
            "cancel_live_response": self._handle_cancel_live_response,
            "run_script_live_response": self._handle_run_script_live_response,
            "get_missing_kbs": self._handle_get_missing_kbs,
            "update_device_tag": self._handle_update_device_tag,
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in list(action_mapping.keys()):
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):
        """This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except Exception as e:
            self._dump_error_log(e, "Error occured while getting the Phantom server's Python major version")
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        self._state = self.load_state()

        self.set_validator("ipv6", self._is_ipv6)

        # get the asset config
        config = self.get_config()

        self._non_interactive = config.get("non_interactive", False)
        self._tenant = config[DEFENDERATP_CONFIG_TENANT_ID]
        self._client_id = config[DEFENDERATP_CONFIG_CLIENT_ID]
        self._client_secret = config[DEFENDERATP_CONFIG_CLIENT_SECRET]
        self._environment = config.get(DEFENDERATP_CONFIG_ENVIRONMENT, "Public")

        self._login_url = DEFENDERATP_LOGIN_BASE_URL
        self._resource_url = DEFENDERATP_RESOURCE_URL
        self._graph_url = DEFENDERATP_MSGRAPH_API_BASE_URL

        if self._environment == "GCC":
            self._login_url = DEFENDERATP_LOGIN_GCC_BASE_URL
            self._resource_url = DEFENDERATP_RESOURCE_GCC_URL
            self._graph_url = DEFENDERATP_MSGRAPH_API_GCC_BASE_URL

        elif self._environment == "GCC High":
            self._login_url = DEFENDERATP_LOGIN_GCC_HIGH_BASE_URL
            self._resource_url = DEFENDERATP_RESOURCE_GCC_HIGH_URL
            self._graph_url = DEFENDERATP_MSGRAPH_API_GCC_HIGH_BASE_URL

        try:
            self._access_token = self._state.get(DEFENDERATP_TOKEN_STRING, {}).get(DEFENDERATP_ACCESS_TOKEN_STRING)
            if not self._non_interactive:
                self._refresh_token = self._state.get(DEFENDERATP_TOKEN_STRING, {}).get(DEFENDERATP_REFRESH_TOKEN_STRING)
        except Exception as e:
            self._dump_error_log(e, "Error occured while parsing the state file.")
            return self.set_status(
                phantom.APP_ERROR,
                "Error occurred while parsing the state file. Please delete the state file and run the test connectivity again",
            )

        return phantom.APP_SUCCESS

    def finalize(self):
        """This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

        # Save the state, this data is saved across actions and app upgrades
        try:
            self.save_state(deepcopy(self._state))
            _save_app_state(self._state, self.get_asset_id(), self)
        except Exception as e:
            self._dump_error_log(e, "Error occured while saving state file.")
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = f"{BaseConnector._get_phantom_base_url()}login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify)  # nosemgrep: python.requests.best-practice.use-timeout.use-timeout
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = f"csrftoken={csrftoken}"
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url,
                verify=verify,
                data=data,
                headers=headers,  # nosemgrep: python.requests.best-practice.use-timeout.use-timeout
            )

            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {e!s}")
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = WindowsDefenderAtpConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
