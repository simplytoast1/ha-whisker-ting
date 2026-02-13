"""Authentication helpers for Whisker Ting using AWS Cognito SRP."""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import hmac
import logging
import os
from typing import Any

import aiohttp

from .const import COGNITO_CLIENT_ID, COGNITO_REGION, COGNITO_USER_POOL_ID

_LOGGER = logging.getLogger(__name__)

# Cognito endpoint
COGNITO_IDP_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/"

# SRP constants (from amazon-cognito-identity-js)
N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
G_HEX = "2"
INFO_BITS = bytearray("Caldera Derived Key", "utf-8")

WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


class AuthenticationError(Exception):
    """Authentication error."""


def hash_sha256(buf: bytes) -> str:
    """Hash using SHA256 and return zero-padded hex string."""
    value = hashlib.sha256(buf).hexdigest()
    return (64 - len(value)) * "0" + value


def hex_hash(hex_string: str) -> str:
    """Hash a hex string."""
    return hash_sha256(bytearray.fromhex(hex_string))


def hex_to_long(hex_string: str) -> int:
    """Convert hex string to long."""
    return int(hex_string, 16)


def long_to_hex(long_num: int) -> str:
    """Convert long to hex string."""
    return f"{long_num:x}"


def get_random(nbytes: int) -> int:
    """Generate random number."""
    random_hex = binascii.hexlify(os.urandom(nbytes))
    return hex_to_long(random_hex.decode())


def pad_hex(long_int: int | str) -> str:
    """Pad hex string with leading zeros if needed."""
    if not isinstance(long_int, str):
        hash_str = long_to_hex(long_int)
    else:
        hash_str = long_int
    if len(hash_str) % 2 == 1:
        hash_str = f"0{hash_str}"
    elif hash_str[0] in "89ABCDEFabcdef":
        hash_str = f"00{hash_str}"
    return hash_str


def compute_hkdf(ikm: bytes, salt: bytes) -> bytes:
    """HKDF-based key derivation."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    info_bits_update = INFO_BITS + bytearray(chr(1), "utf-8")
    hmac_hash = hmac.new(prk, info_bits_update, hashlib.sha256).digest()
    return hmac_hash[:16]


def calculate_u(big_a: int, big_b: int) -> int:
    """Calculate u value."""
    u_hex_hash = hex_hash(pad_hex(big_a) + pad_hex(big_b))
    return hex_to_long(u_hex_hash)


def get_cognito_formatted_timestamp(input_datetime: datetime.datetime) -> str:
    """Format timestamp for Cognito."""
    return (
        f"{WEEKDAY_NAMES[input_datetime.weekday()]} "
        f"{MONTH_NAMES[input_datetime.month - 1]} "
        f"{input_datetime.day:d} "
        f"{input_datetime.hour:02d}:{input_datetime.minute:02d}:{input_datetime.second:02d} "
        f"UTC {input_datetime.year:d}"
    )


class CognitoSRP:
    """Handle AWS Cognito SRP authentication."""

    def __init__(
        self,
        username: str,
        password: str,
        pool_id: str = COGNITO_USER_POOL_ID,
        client_id: str = COGNITO_CLIENT_ID,
    ) -> None:
        """Initialize SRP authentication."""
        self.username = username
        self.password = password
        self.pool_id = pool_id
        self.client_id = client_id

        # SRP values
        self.big_n = hex_to_long(N_HEX)
        self.val_g = hex_to_long(G_HEX)
        self.val_k = hex_to_long(hex_hash("00" + N_HEX + "0" + G_HEX))
        self.small_a_value = self._generate_random_small_a()
        self.large_a_value = self._calculate_a()

    def _generate_random_small_a(self) -> int:
        """Generate random small a value."""
        random_long_int = get_random(128)
        return random_long_int % self.big_n

    def _calculate_a(self) -> int:
        """Calculate large A value."""
        big_a = pow(self.val_g, self.small_a_value, self.big_n)
        if big_a % self.big_n == 0:
            raise ValueError("Safety check for A failed")
        return big_a

    def get_auth_params(self) -> dict[str, str]:
        """Get initial auth parameters."""
        return {
            "USERNAME": self.username,
            "SRP_A": long_to_hex(self.large_a_value),
        }

    def get_password_authentication_key(
        self, username: str, password: str, server_b_value: int, salt: str
    ) -> bytes:
        """Calculate password authentication key."""
        u_value = calculate_u(self.large_a_value, server_b_value)
        if u_value == 0:
            raise ValueError("U cannot be zero.")

        # NOTE: No colon between pool_id and username!
        username_password = f"{self.pool_id.split('_')[1]}{username}:{password}"
        username_password_hash = hash_sha256(username_password.encode("utf-8"))

        x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
        g_mod_pow_xn = pow(self.val_g, x_value, self.big_n)
        int_value2 = server_b_value - self.val_k * g_mod_pow_xn
        s_value = pow(int_value2, self.small_a_value + u_value * x_value, self.big_n)
        hkdf = compute_hkdf(
            bytearray.fromhex(pad_hex(s_value)),
            bytearray.fromhex(pad_hex(long_to_hex(u_value))),
        )
        return hkdf

    def process_challenge(
        self, challenge_parameters: dict[str, str], request_parameters: dict[str, str]
    ) -> dict[str, str]:
        """Process the password verifier challenge."""
        internal_username = challenge_parameters.get(
            "USERNAME", request_parameters["USERNAME"]
        )
        user_id_for_srp = challenge_parameters["USER_ID_FOR_SRP"]
        salt_hex = challenge_parameters["SALT"]
        srp_b_hex = challenge_parameters["SRP_B"]
        secret_block_b64 = challenge_parameters["SECRET_BLOCK"]

        timestamp = get_cognito_formatted_timestamp(datetime.datetime.now(datetime.UTC))

        hkdf = self.get_password_authentication_key(
            user_id_for_srp,
            self.password,
            hex_to_long(srp_b_hex),
            salt_hex,  # Pass as hex string, not converted to long
        )

        secret_block_bytes = base64.standard_b64decode(secret_block_b64)

        msg = (
            bytearray(self.pool_id.split("_")[1], "utf-8")
            + bytearray(user_id_for_srp, "utf-8")
            + bytearray(secret_block_bytes)
            + bytearray(timestamp, "utf-8")
        )
        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signature_string = base64.standard_b64encode(hmac_obj.digest()).decode("utf-8")

        return {
            "TIMESTAMP": timestamp,
            "USERNAME": internal_username,
            "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
            "PASSWORD_CLAIM_SIGNATURE": signature_string,
        }


class WhiskerAuth:
    """Handle Whisker/Cognito authentication flow."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        """Initialize the auth handler."""
        self._session = session

    async def authenticate(self, username: str, password: str) -> dict[str, Any]:
        """Authenticate with username and password, return tokens and user info."""
        srp = CognitoSRP(username, password)

        # Step 1: Initiate auth
        auth_params = srp.get_auth_params()
        init_response = await self._initiate_auth(auth_params)

        if init_response.get("ChallengeName") != "PASSWORD_VERIFIER":
            raise AuthenticationError(
                f"Unexpected challenge: {init_response.get('ChallengeName')}"
            )

        # Step 2: Respond to challenge
        challenge_params = init_response["ChallengeParameters"]
        challenge_response = srp.process_challenge(challenge_params, auth_params)

        auth_result = await self._respond_to_challenge(challenge_response)

        if "AuthenticationResult" not in auth_result:
            raise AuthenticationError("Authentication failed - no result returned")

        tokens = auth_result["AuthenticationResult"]

        # Step 3: Get user attributes
        user_info = await self._get_user(tokens["AccessToken"])

        return {
            "access_token": tokens["AccessToken"],
            "id_token": tokens["IdToken"],
            "refresh_token": tokens["RefreshToken"],
            "user_attributes": user_info.get("UserAttributes", []),
        }

    async def refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        """Refresh access tokens using refresh token."""
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }

        payload = {
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "AuthParameters": {
                "REFRESH_TOKEN": refresh_token,
            },
            "ClientId": COGNITO_CLIENT_ID,
        }

        async with self._session.post(
            COGNITO_IDP_URL, json=payload, headers=headers
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise AuthenticationError(f"Token refresh failed: {text}")

            result = await resp.json(content_type=None)

            if "AuthenticationResult" not in result:
                raise AuthenticationError("Token refresh failed - no result")

            return result["AuthenticationResult"]

    async def _initiate_auth(self, auth_params: dict[str, str]) -> dict[str, Any]:
        """Initiate SRP authentication."""
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }

        payload = {
            "AuthFlow": "USER_SRP_AUTH",
            "AuthParameters": auth_params,
            "ClientId": COGNITO_CLIENT_ID,
        }

        _LOGGER.debug("Initiating SRP auth for user: %s", auth_params.get("USERNAME"))
        async with self._session.post(
            COGNITO_IDP_URL, json=payload, headers=headers
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                if "UserNotFoundException" in text or "NotAuthorizedException" in text:
                    raise AuthenticationError("Invalid username or password")
                raise AuthenticationError(f"Auth initiation failed: {text}")

            return await resp.json(content_type=None)

    async def _respond_to_challenge(
        self, challenge_response: dict[str, str]
    ) -> dict[str, Any]:
        """Respond to password verifier challenge."""
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
        }

        payload = {
            "ChallengeName": "PASSWORD_VERIFIER",
            "ChallengeResponses": challenge_response,
            "ClientId": COGNITO_CLIENT_ID,
        }

        _LOGGER.debug("Responding to challenge for user: %s", challenge_response.get("USERNAME"))
        async with self._session.post(
            COGNITO_IDP_URL, json=payload, headers=headers
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                _LOGGER.debug("Challenge response failed: %s", text)
                if "NotAuthorizedException" in text:
                    raise AuthenticationError("Invalid username or password")
                raise AuthenticationError(f"Challenge response failed: {text}")

            return await resp.json(content_type=None)

    async def _get_user(self, access_token: str) -> dict[str, Any]:
        """Get user attributes from Cognito."""
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.GetUser",
        }

        payload = {
            "AccessToken": access_token,
        }

        async with self._session.post(
            COGNITO_IDP_URL, json=payload, headers=headers
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise AuthenticationError(f"Failed to get user info: {text}")

            return await resp.json(content_type=None)
