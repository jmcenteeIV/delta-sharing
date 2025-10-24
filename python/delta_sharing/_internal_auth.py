#
# Copyright (C) 2021 The Delta Lake Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional
import requests
import base64
import json
import threading
import requests.sessions
import time
from typing import Dict

from delta_sharing.protocol import (
    DeltaSharingProfile,
)

# This module contains internal implementation classes.
# These classes are not part of the public API and should not be used directly by users.
# Internal classes may change or be removed at any time without notice.


class AuthConfig:
    def __init__(
        self,
        token_exchange_max_retries=5,
        token_exchange_max_retry_duration_in_seconds=60,
        token_renewal_threshold_in_seconds=600,
    ):
        self.token_exchange_max_retries = token_exchange_max_retries
        self.token_exchange_max_retry_duration_in_seconds = (
            token_exchange_max_retry_duration_in_seconds
        )
        self.token_renewal_threshold_in_seconds = token_renewal_threshold_in_seconds


class AuthCredentialProvider(ABC):
    @abstractmethod
    def add_auth_header(self, session: requests.Session) -> None:
        pass

    def is_expired(self) -> bool:
        return False

    @abstractmethod
    def get_expiration_time(self) -> Optional[str]:
        return None


class BearerTokenAuthProvider(AuthCredentialProvider):
    def __init__(self, bearer_token: str, expiration_time: Optional[str]):
        self.bearer_token = bearer_token
        self.expiration_time = expiration_time

    def add_auth_header(self, session: requests.Session) -> None:
        session.headers.update(
            {
                "Authorization": f"Bearer {self.bearer_token}",
            }
        )

    def is_expired(self) -> bool:
        if self.expiration_time is None:
            return False
        try:
            expiration_time_as_timestamp = datetime.fromisoformat(self.expiration_time)
            return expiration_time_as_timestamp < datetime.now()
        except ValueError:
            return False

    def get_expiration_time(self) -> Optional[str]:
        return self.expiration_time


class BasicAuthProvider(AuthCredentialProvider):
    def __init__(self, endpoint: str, username: str, password: str):
        self.username = username
        self.password = password
        self.endpoint = endpoint

    def add_auth_header(self, session: requests.Session) -> None:
        session.auth = (self.username, self.password)
        session.post(
            self.endpoint,
            data={"grant_type": "client_credentials"},
        )

    def is_expired(self) -> bool:
        return False

    def get_expiration_time(self) -> Optional[str]:
        return None


class OAuthClientCredentials:
    def __init__(self, access_token: str, expires_in: int, creation_timestamp: int):
        self.access_token = access_token
        self.expires_in = expires_in
        self.creation_timestamp = creation_timestamp

class OAuthInteractiveGrantClientCredentials(OAuthClientCredentials):
    def __init__(
        self,
        access_token: str,
        expires_in: int,
        creation_timestamp: int,
        refresh_token: str,
        scope: str,
    ):
        super().__init__(access_token, expires_in, creation_timestamp)
        self.refresh_token = refresh_token
        self.scope = scope



class OAuthClient:
    def __init__(
        self, token_endpoint: str, client_id: str, client_secret: str, scope: Optional[str] = None
    ):
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope

    def client_credentials(self) -> OAuthClientCredentials:
        credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode("utf-8")
        ).decode("utf-8")
        headers = {
            "accept": "application/json",
            "authorization": f"Basic {credentials}",
            "content-type": "application/x-www-form-urlencoded",
        }
        body = f"grant_type=client_credentials{f'&scope={self.scope}' if self.scope else ''}"
        response = requests.post(self.token_endpoint, headers=headers, data=body)
        response.raise_for_status()
        return self.parse_oauth_token_response(response.text)

    def parse_oauth_token_response(self, response: str) -> OAuthClientCredentials:
        if not response:
            raise RuntimeError("Empty response from OAuth token endpoint")
        # Parsing the response per oauth spec
        # https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
        json_node = json.loads(response)
        if "access_token" not in json_node or not isinstance(json_node["access_token"], str):
            raise RuntimeError("Missing 'access_token' field in OAuth token response")
        if "expires_in" not in json_node:
            raise RuntimeError("Missing 'expires_in' field in OAuth token response")
        try:
            # OAuth spec requires 'expires_in' to be an integer, e.g., 3600.
            # See https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
            # But some token endpoints return `expires_in` as a string e.g., "3600".
            # This ensures that we support both integer and string values for 'expires_in' field.
            # Example request resulting in 'expires_in' as a string:
            # curl -X POST \
            #   https://login.windows.net/$TENANT_ID/oauth2/token \
            #   -H "Content-Type: application/x-www-form-urlencoded" \
            #   -d "grant_type=client_credentials" \
            #   -d "client_id=$CLIENT_ID" \
            #   -d "client_secret=$CLIENT_SECRET" \
            #   -d "scope=https://graph.microsoft.com/.default"
            expires_in = int(json_node["expires_in"])  # Convert to int if it's a string
        except ValueError:
            raise RuntimeError(
                "'expires_in' field must be an integer or a string convertible to integer"
            )
        return OAuthClientCredentials(
            json_node["access_token"], expires_in, int(datetime.now().timestamp())
        )

class OAuthInteractiveGrantClient:
    def __init__(
        self, issuer: str, client_id: str, token_url: str, refresh_url: str, device_auth_url: str, client_secret: Optional[str] = None, scope: Optional[str] = None
    ):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.token_url = token_url
        self.refresh_url = refresh_url
        self.device_auth_url = device_auth_url

    def client_credentials(self, refresh_token: Optional[str] = None) -> OAuthInteractiveGrantClientCredentials:
        with requests.Session() as session:
            if refresh_token:
                try:
                    token_response = self.refresh_token(session)
                    return OAuthInteractiveGrantClientCredentials(
                        access_token=token_response["access_token"],
                        expires_in=token_response["expires_in"],
                        creation_timestamp=int(datetime.now().timestamp()),
                        refresh_token=token_response.get("refresh_token", refresh_token),
                        scope=token_response.get("scope", self.scope),
                    )
                except Exception as e:
                    print(f"Refresh token failed: {e}. Falling back to device authorization flow.")
            # 1) Start device authorization
            device = self.start_device_authorization(session)

            # 2) Tell the user what to do (copy/paste friendly)
            print("\n=== Delta Sharing OIDC (Device Flow) ===\n")
            print("Please complete sign-in on any browser:")
            print(f"  Verification URL: {device['verification_uri']}")
            # Some Keycloak versions also provide 'verification_uri_complete'
            if "verification_uri_complete" in device:
                print(f"  (Direct link):    {device['verification_uri_complete']}")
            print(f"  User code:        {device['user_code']}\n")

            # 3) Poll until the user finishes
            print(f"Waiting for authorization.  Timeout in {device['expires_in']} seconds...")
            token_response = self.poll_for_token(session, device)
            return OAuthInteractiveGrantClientCredentials(
                access_token=token_response["access_token"],
                expires_in=token_response["expires_in"],
                creation_timestamp=int(datetime.now().timestamp()),
                refresh_token=token_response.get("refresh_token", ""),
                scope=token_response.get("scope", self.scope),
            )


    def start_device_authorization(self, session: requests.Session) -> Dict[str, Any]:
        """Initiate device authorization; return device_code payload."""
        data = {
            "client_id": self.client_id,
            "scope": self.scope,
            "client_secret": self.client_secret,
        }
        # RFC 8628 recommends application/x-www-form-urlencoded
        resp = session.post(self.device_auth_url, data=data, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        required = {"device_code", "user_code", "verification_uri", "expires_in"}
        if not required.issubset(payload):
            raise RuntimeError(f"Unexpected device response: {payload}")
        return payload
    
    def poll_for_token(self, session: requests.Session, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Poll Keycloak token endpoint with the device_code until:
        - access_token is returned, or
        - the device code expires, or
        - an error occurs.
        Handles authorization_pending / slow_down per RFC 8628.
        """
        device_code = device["device_code"]
        interval = int(device.get("interval", 5))  # default polling interval seconds
        deadline = time.time() + int(device["expires_in"])

        while True:
            if time.time() >= deadline:
                raise TimeoutError("Device code expired before authorization was completed.")

            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            resp = session.post(self.token_url, data=data, timeout=30)
            # 200 OK => either tokens or error JSON
            try:
                payload = resp.json()
            except Exception:
                resp.raise_for_status()
                payload = {}  # unreachable if above succeeds

            if "access_token" in payload:
                return payload

            error = payload.get("error")
            if error == "authorization_pending":
                time.sleep(interval)
                continue
            elif error == "slow_down":
                interval += 5
                time.sleep(interval)
                continue
            elif error in {"expired_token", "access_denied"}:
                raise RuntimeError(f"Authorization failed: {error}")
            else:
                # Could be invalid_client, invalid_scope, etc.
                # If HTTP status indicates a hard failure, raise; otherwise show payload.
                if resp.status_code >= 400:
                    raise RuntimeError(f"Token polling failed ({resp.status_code}): {payload}")
                time.sleep(interval)

    def refresh_token(self, session: requests.Session) -> Dict[str, Any]:
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.current_token.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        resp = session.post(self.token_url, data=data, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        if "access_token" not in payload:
            raise RuntimeError(f"Unexpected refresh token response: {payload}")
        return payload


class OAuthClientCredentialsAuthProvider(AuthCredentialProvider):
    def __init__(self, oauth_client: OAuthClient, auth_config: AuthConfig = AuthConfig()):
        self.auth_config = auth_config
        self.oauth_client = oauth_client
        self.current_token: Optional[OAuthClientCredentials] = None
        self.lock = threading.RLock()

    def add_auth_header(self, session: requests.Session) -> None:
        token = self.maybe_refresh_token()
        with self.lock:
            session.headers.update(
                {
                    "Authorization": f"Bearer {token.access_token}",
                }
            )

    def maybe_refresh_token(self) -> OAuthClientCredentials:
        with self.lock:
            if self.current_token and not self.needs_refresh(self.current_token):
                return self.current_token
            new_token = self.oauth_client.client_credentials()
            self.current_token = new_token
            return new_token

    def needs_refresh(self, token: OAuthClientCredentials) -> bool:
        now = int(time.time())
        expiration_time = token.creation_timestamp + token.expires_in
        return expiration_time - now < self.auth_config.token_renewal_threshold_in_seconds

    def get_expiration_time(self) -> Optional[str]:
        return None

class OAuthClientInteractiveGrantAuthProvider(AuthCredentialProvider):
    def __init__(self, oauth_client: OAuthInteractiveGrantClient, auth_config: AuthConfig = AuthConfig()):
        self.auth_config = auth_config
        self.oauth_client = oauth_client
        self.current_token: Optional[OAuthInteractiveGrantClientCredentials] = None
        self.lock = threading.RLock()

    def add_auth_header(self, session: requests.Session) -> None:
        token = self.maybe_refresh_token()
        with self.lock:
            session.headers.update(
                {
                    "Authorization": f"Bearer {token.access_token}",
                }
            )

    def maybe_refresh_token(self) -> OAuthInteractiveGrantClientCredentials:
        with self.lock:
            if self.current_token and not self.needs_refresh(self.current_token):
                return self.current_token
            new_token = self.oauth_client.client_credentials()
            self.current_token = new_token
            return new_token

    def needs_refresh(self, token: OAuthInteractiveGrantClientCredentials) -> bool:
        now = int(time.time())
        expiration_time = token.creation_timestamp + token.expires_in
        return expiration_time - now < self.auth_config.token_renewal_threshold_in_seconds

    def get_expiration_time(self) -> Optional[str]:
        return None

class AuthCredentialProviderFactory:
    __oauth_auth_provider_cache: Dict[DeltaSharingProfile, OAuthClientCredentialsAuthProvider] = {}

    @staticmethod
    def create_auth_credential_provider(profile: DeltaSharingProfile):
        if profile.share_credentials_version == 3:
            if profile.type == "oauth_client_oidc_interactive":
                return AuthCredentialProviderFactory.__oauth_client_interactive_grant(profile)
            elif profile.type == "basic":
                return AuthCredentialProviderFactory.__auth_basic(profile)
        elif profile.share_credentials_version == 2:
            if profile.type == "oauth_client_credentials":
                return AuthCredentialProviderFactory.__oauth_client_credentials(profile)
            elif profile.type == "basic":
                return AuthCredentialProviderFactory.__auth_basic(profile)
        elif profile.share_credentials_version == 1 and (
            profile.type is None or profile.type == "bearer_token"
        ):
            return AuthCredentialProviderFactory.__auth_bearer_token(profile)

        # any other scenario is unsupported
        raise RuntimeError(
            f"unsupported profile.type: {profile.type}"
            f" profile.share_credentials_version"
            f" {profile.share_credentials_version}"
        )

    @staticmethod
    def __oauth_client_credentials(profile):
        # Once a clientId/clientSecret is exchanged for an accessToken,
        # the accessToken can be reused until it expires.
        # The Python client re-creates DeltaSharingClient for different requests.
        # To ensure the OAuth access_token is reused,
        # we keep a mapping from profile -> OAuthClientCredentialsAuthProvider.
        # This prevents re-initializing OAuthClientCredentialsAuthProvider for the same profile,
        # ensuring the access_token can be reused.
        if profile in AuthCredentialProviderFactory.__oauth_auth_provider_cache:
            return AuthCredentialProviderFactory.__oauth_auth_provider_cache[profile]

        oauth_client = OAuthClient(
            token_endpoint=profile.token_endpoint,
            client_id=profile.client_id,
            client_secret=profile.client_secret,
            scope=profile.scope,
        )
        provider = OAuthClientCredentialsAuthProvider(
            oauth_client=oauth_client, auth_config=AuthConfig()
        )
        AuthCredentialProviderFactory.__oauth_auth_provider_cache[profile] = provider
        return provider

    @staticmethod
    def __auth_bearer_token(profile):
        return BearerTokenAuthProvider(profile.bearer_token, profile.expiration_time)

    @staticmethod
    def __auth_basic(profile):
        return BasicAuthProvider(profile.endpoint, profile.username, profile.password)
    
    @staticmethod
    def __oauth_client_interactive_grant(profile):
        well_known_url = f"{profile.issuer}/.well-known/openid-configuration"
        try:
            response = requests.get(well_known_url)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching well-known configuration: {e}")
            return None
        config = response.json()
        if not config.get("device_authorization_endpoint"):
            raise RuntimeError(
                f"Device authorization endpoint not found in well-known configuration from {well_known_url}"
            )
        client = OAuthInteractiveGrantClient(
            issuer=profile.issuer,
            client_id=profile.client_id,
            token_url=config.get("token_endpoint"),
            refresh_url=config.get("token_endpoint"),
            device_auth_url=config.get("device_authorization_endpoint"),
            client_secret=profile.client_secret,
            scope=profile.scope,
        )
        provider = OAuthClientInteractiveGrantAuthProvider(
            oauth_client=client, auth_config=AuthConfig()
        )
        AuthCredentialProviderFactory.__oauth_auth_provider_cache[profile] = provider
        return provider
