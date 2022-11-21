from __future__ import annotations

import datetime
import json
import logging
import ssl
from base64 import b64decode, urlsafe_b64encode
from typing import NoReturn, Optional

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key
from urllib3.poolmanager import PoolManager
from urllib3.util import ssl_

from . import googleplay_pb2, device, utils

log_format = "%(asctime)s: %(message)s"
logging.basicConfig(format=log_format, level=logging.INFO, datefmt="%H:%M:%S")
ssl_verify = True

GOOGLE_PUBKEY = (
    "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nK"
    "J3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0Q"
    "RNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ=="
)

URL_BASE = "https://android.clients.google.com/"
FDFE = URL_BASE + "fdfe/"
AUTH_URL = URL_BASE + "auth"
CHECKIN_URL = URL_BASE + "checkin"
UPLOAD_URL = FDFE + "uploadDeviceConfig"
DETAILS_URL = FDFE + "details"
BROWSE_URL = FDFE + "browse"
LIST_TOP_CHART_URL = FDFE + "listTopChartItems"
TOC_URL = FDFE + "toc"
ACCEPT_TOS_URL = FDFE + "acceptTos"

CONTENT_TYPE_URLENC = "application/x-www-form-urlencoded; charset=UTF-8"
CONTENT_TYPE_PROTO = "application/x-protobuf"


class SSLContext(ssl.SSLContext):
    def set_alpn_protocols(self, protocols):
        """
        ALPN headers cause Google to return 403 Bad Authentication.
        """
        pass


class AuthHTTPAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        """
        Secure settings from ssl.create_default_context(), but without
        ssl.OP_NO_TICKET which causes Google to return 403 Bad
        Authentication.
        """
        context = SSLContext()
        context.set_ciphers(ssl_.DEFAULT_CIPHERS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.options &= ~0x4000
        self.poolmanager = PoolManager(*args, ssl_context=context, **kwargs)


class GooglePlayAPI(object):
    """
    Unofficial Google Play API.
    """

    def __init__(
        self,
        device_codename: str,
        locale: str,
        timezone: str,
        proxies_config: Optional[dict] = None,
    ) -> NoReturn:
        self.device_codename = device_codename
        self.locale = locale
        self.timezone = timezone
        self.device = device.AndroidDevice.load(device_codename, locale, timezone)
        self.proxies_config = proxies_config
        self.aas_token = None
        self.ac2dm_token = None
        self.googleplay_token = None
        # Unix timestamp in UTC representing the expiration date for Google Play token.
        self.gp_token_expiry = None
        # GSF ID stands for Google Services Framework Identifier. The GSF ID is a unique 16 character
        # hexadecimal number. Your device automatically requests a new one (if it doesn’t have one
        # already) from Google as soon as you log your Google Account in on it for the first time.
        # The assignment is permanent. Once a GSF ID is registered to your account, you can’t remove it
        # ever again (you can only stop using it).
        # Source: https://raccoon.onyxbits.de/blog/what-exactly-is-a-gsf-id-where-do-i-get-it-from-and-why-should-i-care-2-12/
        self.gsf_id = None
        self.device_config_token = None
        self.device_checkin_consistency_token = None
        self.dfe_cookie = None
        self.session = requests.session()
        self.session.mount("https://", AuthHTTPAdapter())

    def save(self, email: str) -> NoReturn:
        with open(f"account-{email}.bak", "w") as w:
            data = {
                "device_codename": self.device_codename,
                "locale": self.locale,
                "timezone": self.timezone,
                "aas_token": self.aas_token,
                "ac2dm_token": self.ac2dm_token,
                "googleplay_token": self.googleplay_token,
                "gp_token_expiry": self.gp_token_expiry,
                "gsf_id": self.gsf_id,
                "device_config_token": self.device_config_token,
                "device_checkin_consistency_token": self.device_checkin_consistency_token,
                "dfe_cookie": self.dfe_cookie,
            }
            w.write(json.dumps(data))

    def dump_config(self) -> dict:
        data = {
            "device_codename": self.device_codename,
            "locale": self.locale,
            "timezone": self.timezone,
            "aas_token": self.aas_token,
            "ac2dm_token": self.ac2dm_token,
            "googleplay_token": self.googleplay_token,
            "gp_token_expiry": self.gp_token_expiry,
            "gsf_id": self.gsf_id,
            "device_config_token": self.device_config_token,
            "device_checkin_consistency_token": self.device_checkin_consistency_token,
            "dfe_cookie": self.dfe_cookie,
        }
        return data

    @classmethod
    def load_config(cls, data: dict) -> GooglePlayAPI:
        gpapi = cls(data["device_codename"], data["locale"], data["timezone"])
        gpapi.aas_token = data["aas_token"]
        gpapi.ac2dm_token = data["ac2dm_token"]
        gpapi.googleplay_token = data["googleplay_token"]
        if "gp_token_expiry" in data:
            gpapi.gp_token_expiry = data["gp_token_expiry"]
        gpapi.gsf_id = data["gsf_id"]
        gpapi.device_config_token = data["device_config_token"]
        gpapi.device_checkin_consistency_token = data[
            "device_checkin_consistency_token"
        ]
        gpapi.dfe_cookie = data["dfe_cookie"]
        return gpapi

    @classmethod
    def load(cls, email: str) -> GooglePlayAPI:
        with open(f"account-{email}.bak") as f:
            data = json.loads(f.read())
            gpapi = cls(data["device_codename"], data["locale"], data["timezone"])
            gpapi.aas_token = data["aas_token"]
            gpapi.ac2dm_token = data["ac2dm_token"]
            gpapi.googleplay_token = data["googleplay_token"]
            if "gp_token_expiry" in data:
                gpapi.gp_token_expiry = data["gp_token_expiry"]
            gpapi.gsf_id = data["gsf_id"]
            gpapi.device_config_token = data["device_config_token"]
            gpapi.device_checkin_consistency_token = data[
                "device_checkin_consistency_token"
            ]
            gpapi.dfe_cookie = data["dfe_cookie"]
        return gpapi

    def encrypt_password(self, login: str, passwd: str) -> str:
        """
        Encrypt credentials using the Google publickey, with the RSA algorithm.
        The structure of the binary key:

        *-------------------------------------------------------*
        | modulus_length | modulus | exponent_length | exponent |
        *-------------------------------------------------------*

        Modulus_length and exponent_length are uint32.
        """
        binary_key = b64decode(GOOGLE_PUBKEY)
        # modulus
        i = utils.readInt(binary_key, 0)
        modulus = utils.toBigInt(binary_key[4:][0:i])
        # exponent
        j = utils.readInt(binary_key, i + 4)
        exponent = utils.toBigInt(binary_key[i + 8 :][0:j])

        # calculate SHA1 of the pub key
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(binary_key)
        h = b"\x00" + digest.finalize()[0:4]

        # generate a public key
        der_data = encode_dss_signature(modulus, exponent)
        publicKey = load_der_public_key(der_data, backend=default_backend())

        # encrypt email and password using pubkey
        to_be_encrypted = login.encode() + b"\x00" + passwd.encode()
        ciphertext = publicKey.encrypt(
            to_be_encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        return urlsafe_b64encode(h + ciphertext)

    def login(self, email: str, password: str) -> NoReturn:
        """
        Login to your Google Account. You should do this only once to obtain the master token and
        upload the device config. It effectively adds a new device to your Google Account.
        Args:
          email (str): The email address.
          password (str): The password.
        """
        encrypted_passwd = self.encrypt_password(email, password).decode("utf-8")
        login_data = {
            "Email": email,
            "EncryptedPasswd": encrypted_passwd,
            "add_account": "1",
            "accountType": "HOSTED_OR_GOOGLE",
            "google_play_services_version": self.device.conf.get("gsf.version"),
            "has_permission": "1",
            "source": "android",
            "device_country": self.device.country,
            "operatorCountry": self.device.country,
            "lang": self.device.locale,
            "sdk_version": 17,
            "client_sig": "38918a453d07199354f8b19af05ec6562ced5788",
            "callerSig": "38918a453d07199354f8b19af05ec6562ced5788",
        }
        # We use Android C2DM service to get ClientLogin token.
        # Other 'service' seen in the wild to be used: 'sj'
        login_data["service"] = "ac2dm"
        login_data["callerPkg"] = "com.google.android.gms"

        self.session.headers = {"User-Agent": "GoogleAuth/1.4"}
        response = self.session.post(
            AUTH_URL, data=login_data, verify=ssl_verify, proxies=self.proxies_config
        )

        data = self.parse_response(response)
        print(data)
        if not response.ok or "error" in data:
            if "NeedsBrowser" in data["error"]:
                raise SecurityCheckError(
                    "Security check is needed, try to visit "
                    "https://accounts.google.com/b/0/DisplayUnlockCaptcha "
                    "to unlock, or setup an app-specific password."
                )
            else:
                raise LoginError(data["error"])

        else:
            if "auth" in data:
                self.ac2dm_token = data.get("auth")
            # Extract the master token which we use to obtain OAuth tokens.
            if "token" in data:
                self.aas_token = data.get("token")
            else:
                raise LoginError(f"AAS token not found in response:\n {repr(data)}")

    def generate_gsf_id(self):
        """
        GSF ID is what Android ID was intended to be. The GSF ID is generated server side and
        requested by the device when an account is added to it (every user gets his own GSF ID).
        After being assigned a GSF ID, the device will bind the account to it.
        """
        request = self.device.get_android_checkin_request()

        # Checkin request which sends device specific attributes and retrieves unique GSF ID.
        headers = {}
        # We don't need "app" for generating GSF ID.
        headers["app"] = "com.google.android.gms"
        headers["User-Agent"] = self.device.getUserAgent()
        headers["Content-Type"] = CONTENT_TYPE_PROTO
        res = self.session.post(
            CHECKIN_URL,
            data=request.SerializeToString(),
            headers=headers,
            verify=ssl_verify,
            proxies=self.proxies_config,
        )
        response = googleplay_pb2.AndroidCheckinResponse()
        response.ParseFromString(res.content)
        self.device_checkin_consistency_token = response.deviceCheckinConsistencyToken
        self.gsf_id = response.androidId

    def parse_response(self, response: requests.Response) -> dict:
        """
        Parse response data which is in the following format:
        KEY=VALUE\n
        Args:
          response (requests.Response): Response object.
        Returns:
          A dict containing parsed key value pairs.
        """
        data = {}
        for line in response.iter_lines():
            if b"=" not in line:
                continue
            key, value = line.decode("utf-8").split("=", 1)
            data[key.lower()] = value
        return data

    def get_default_headers(self):
        pass

    def get_auth_headers(self):
        pass

    def getHeaders(self, upload_fields=False):
        """Return the default set of request headers, which
        can later be expanded, based on the request type"""

        if upload_fields:
            headers = self.device.getDeviceUploadHeaders()
        else:
            headers = self.device.getBaseHeaders()

        if self.gsfId is not None:
            headers["X-DFE-Device-Id"] = "{0:x}".format(self.gsf_id)
        if self.authSubToken is not None:
            headers["Authorization"] = "GoogleLogin auth=%s" % self.authSubToken
        if self.device_config_token is not None:
            headers["X-DFE-Device-Config-Token"] = self.device_config_token
        if self.deviceCheckinConsistencyToken is not None:
            headers[
                "X-DFE-Device-Checkin-Consistency-Token"
            ] = self.deviceCheckinConsistencyToken
        if self.dfeCookie is not None:
            headers["X-DFE-Cookie"] = self.dfeCookie
        return headers

    def upload_device_config(self):
        """
        Upload the device configuration of the fake device
        selected in the __init__ methodi to the google account.
        """

        request = googleplay_pb2.UploadDeviceConfigRequest()
        request.deviceConfiguration.CopyFrom(self.device.getDeviceConfig())
        headers = {
            "Accept-Language": self.device.locale.replace("_", "-"),
            "User-Agent": self.device.getUserAgent(),
            "X-DFE-Encoded-Targets": device.DFE_TARGETS,
            "X-DFE-Client-Id": "am-android-google",
            "X-DFE-MCCMNC": self.device.conf.get("celloperator"),
            "X-DFE-Network-Type": "4",
            "X-DFE-Content-Filters": "",
            "X-DFE-Request-Params": "timeoutMs=4000",
        }
        headers["X-Limit-Ad-Tracking-Enabled"] = "false"

        if self.googleplay_token is not None:
            headers["Authorization"] = f"Bearer {self.googleplay_token}"
        if self.gsf_id is not None:
            headers["X-DFE-Device-Id"] = "{0:x}".format(self.gsf_id)
        if self.device_checkin_consistency_token is not None:
            headers[
                "X-DFE-Device-Checkin-Consistency-Token"
            ] = self.device_checkin_consistency_token

        response = self.session.post(
            UPLOAD_URL,
            headers=headers,
            data=request.SerializeToString(),
            verify=ssl_verify,
            timeout=60,
            proxies=self.proxies_config,
        )
        response = googleplay_pb2.ResponseWrapper.FromString(response.content)
        try:
            if response.payload.HasField("uploadDeviceConfigResponse"):
                self.device_config_token = response.payload.uploadDeviceConfigResponse
                self.device_config_token = (
                    self.device_config_token.uploadDeviceConfigToken
                )
        except ValueError:
            # Other implementations allow for this field to be missing and do nothing.
            # We follow the lead here.
            pass

    def get_token(self, service, email):
        """
        Get temporary OAuth token for Google Play Services.
        """
        headers = {
            "app": "com.google.android.gsm",
            "User-Agent": "GoogleAuth/1.4 ({device} {build_id})".format(
                device=self.device.conf.get("build.device"),
                build_id=self.device.conf.get("build.id"),
            ),
        }
        payload = {
            "androidId": self.gsf_id,
            "sdk_version": self.device.conf.get("build.version.sdk_int"),
            "Email": email,
            "google_play_services_version": self.device.conf.get("gsf.version"),
            "device_country": self.device.country,
            "lang": self.device.locale.replace("_", "-"),
            "callerSig": "38918a453d07199354f8b19af05ec6562ced5788",
            "app": "com.android.vending",
            "client_sig": "38918a453d07199354f8b19af05ec6562ced5788",
            "callerPkg": "com.google.android.gms",
            "Token": self.aas_token,
            "oauth2_foreground": "1",
            "token_request_options": "CAA4AVAB",
            "check_email": "1",
            "system_partition": "1",
        }

        if service == "GOOGLE_PLAY":
            headers["app"] = "com.android.vending"
            payload["service"] = "oauth2:https://www.googleapis.com/auth/googleplay"
            response = self.session.post(
                AUTH_URL,
                headers=headers,
                data=payload,
                verify=ssl_verify,
                proxies=self.proxies_config,
            )
            data = self.parse_response(response)
            if response.ok:
                if "auth" in data:
                    self.googleplay_token = data["auth"]
                if "expiry" in data:
                    # Expiration timestamp seems to be returned in local TZ.
                    # We convert it to before storing UTC.
                    expiry = datetime.datetime.fromtimestamp(int(data["expiry"]))
                    self.gp_token_expiry = int(
                        expiry.replace(tzinfo=datetime.timezone.utc).timestamp()
                    )
            else:
                print(repr(data))

    def details(self, bundle_id):
        """Get app details from a package name.
        packageName is the app unique ID (usually starting with 'com.')."""
        path = DETAILS_URL + "?doc={}".format(requests.utils.quote(bundle_id))
        data = self.call(path)
        return utils.parseProtobufObj(data.payload.detailsResponse.docV2)

    def browse(self, cat=None, subCat=None):
        """Browse categories. If neither cat nor subcat are specified,
        return a list of categories, otherwise it return a list of apps
        using cat (category ID) and subCat (subcategory ID) as filters."""
        path = BROWSE_URL + "?c=3"
        if cat is not None:
            path += "&cat={}".format(requests.utils.quote(cat))
        if subCat is not None:
            path += "&ctr={}".format(requests.utils.quote(subCat))
        data = self.call(path)
        return utils.parseProtobufObj(data.payload.browseResponse)

    def toc(self):
        headers = {}
        response = self.session.get(
            TOC_URL,
            headers=headers,
            verify=ssl_verify,
            timeout=60,
            proxies=self.proxies_config,
        )
        data = googleplay_pb2.ResponseWrapper.FromString(response.content)
        toc_response = data.payload.tocResponse
        if utils.hasTosContent(toc_response) and utils.hasTosToken(toc_response):
            self.accept_tos(toc_response.tosToken)
        if utils.hasCookie(toc_response):
            self.dfe_cookie = toc_response.cookie
        return utils.parseProtobufObj(toc_response)

    def accept_tos(self, tosToken):
        headers = {}
        params = {"tost": tosToken, "toscme": "false"}
        response = self.session.get(
            ACCEPT_TOS_URL,
            headers=headers,
            params=params,
            verify=ssl_verify,
            timeout=60,
            proxies=self.proxies_config,
        )
        data = googleplay_pb2.ResponseWrapper.FromString(response.content)
        return utils.parseProtobufObj(data.payload.acceptTosResponse)

    def list_ranks(self, cat, ctr, next_page_url=None):
        """
        List top ranks for the given category and rank list.
        Args:
          cat (str) - Category ID.
          ctr (str) - Rank list ID.
          nb_results (int) - Number of results per request.
          next_page_url (str) - Next page url for subsequent requests.
        Returns:
          (a list of apps, next page url)
        """
        if next_page_url:
            path = FDFE + next_page_url
        else:
            path = LIST_TOP_CHART_URL + "?c=3&scat={}".format(requests.utils.quote(cat))
            path += "&stcid={}".format(requests.utils.quote(ctr))

        data = self.call(path)
        apps = []
        for d in data.payload.listResponse.doc:  # categories
            for c in d.child:  # sub-category
                for a in c.child:  # app
                    apps.append(utils.parseProtobufObj(a))
        try:
            # Sometimes we get transient very short response which indicates there's no more data
            next_page_url = (
                data.payload.listResponse.doc[0].child[0].containerMetadata.nextPageUrl
            )
        except Exception:
            return (apps, "")
        return (apps, next_page_url)

    def call(self, path, post_data=None, content_type=CONTENT_TYPE_URLENC, params=None):
        if self.googleplay_token is None:
            raise LoginError("You need to login before executing any request")
        headers = {
            "Accept-Language": self.device.locale.replace("_", "-"),
            "X-DFE-Encoded-Targets": device.DFE_TARGETS,
            "User-Agent": self.device.getUserAgent(),
            "X-DFE-Client-Id": "am-android-google",
            "X-DFE-MCCMNC": self.device.conf.get("celloperator"),
            "X-DFE-Network-Type": "4",
            "X-DFE-Content-Filters": "",
            "X-DFE-Request-Params": "timeoutMs=4000",
        }
        if self.gsf_id is not None:
            headers["X-DFE-Device-Id"] = "{0:x}".format(self.gsf_id)
        if self.googleplay_token is not None:
            headers["Authorization"] = "Bearer %s" % self.googleplay_token
        if self.device_config_token is not None:
            headers["X-DFE-Device-Config-Token"] = self.device_config_token
        if self.device_checkin_consistency_token is not None:
            headers[
                "X-DFE-Device-Checkin-Consistency-Token"
            ] = self.device_checkin_consistency_token
        if self.dfe_cookie is not None:
            headers["X-DFE-Cookie"] = self.dfe_cookie
        headers["Content-Type"] = content_type

        if post_data is not None:
            response = self.session.post(
                path,
                data=str(post_data),
                headers=headers,
                params=params,
                verify=ssl_verify,
                timeout=60,
                proxies=self.proxies_config,
            )
        else:
            response = self.session.get(
                path,
                headers=headers,
                params=params,
                verify=ssl_verify,
                timeout=60,
                proxies=self.proxies_config,
            )

        message = googleplay_pb2.ResponseWrapper.FromString(response.content)
        if message.commands.displayErrorMessage != "":
            raise RequestError(message.commands.displayErrorMessage)

        return message


class LoginError(Exception):
    pass


class RequestError(Exception):
    pass


class SecurityCheckError(Exception):
    pass
