"""Config flow for Whisker Ting integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import WhiskerApiClient, WhiskerAuthError, WhiskerConnectionError
from .auth import AuthenticationError
from .const import (
    CONF_ALERT_NOTIFICATIONS,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    CONF_VOLTAGE_PUBLISH_INTERVAL,
    DEFAULT_ALERT_NOTIFICATIONS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_VOLTAGE_PUBLISH_INTERVAL,
    DOMAIN,
    MAX_SCAN_INTERVAL,
    MAX_VOLTAGE_PUBLISH_INTERVAL,
    MIN_SCAN_INTERVAL,
    MIN_VOLTAGE_PUBLISH_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)


class WhiskerConfigFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Whisker Ting."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return WhiskerOptionsFlowHandler()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]

            session = async_get_clientsession(self.hass)
            client = WhiskerApiClient(session, username, password)

            try:
                # Test authentication and get user data
                user_data = await client.get_user_data()
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except WhiskerAuthError:
                errors["base"] = "invalid_auth"
            except WhiskerConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected exception during login")
                errors["base"] = "unknown"
            else:
                # Use user_id as unique identifier
                await self.async_set_unique_id(str(user_data.user_id))
                self._abort_if_unique_id_configured()

                # Create a nice title
                if user_data.first_name:
                    title = (
                        f"Whisker Ting ({user_data.first_name} {user_data.last_name})"
                    )
                else:
                    title = f"Whisker Ting ({username})"

                return self.async_create_entry(
                    title=title,
                    data={
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Handle reauth."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]

            session = async_get_clientsession(self.hass)
            client = WhiskerApiClient(session, username, password)

            try:
                user_data = await client.get_user_data()
            except (AuthenticationError, WhiskerAuthError):
                errors["base"] = "invalid_auth"
            except WhiskerConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected exception during reauth")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(str(user_data.user_id))
                self._abort_if_unique_id_mismatch(reason="wrong_account")

                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(),
                    data_updates={
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    },
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )


class WhiskerOptionsFlowHandler(OptionsFlow):
    """Handle options flow for Whisker Ting."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage general settings."""
        if user_input is not None:
            # Merge over existing options: internal keys (e.g. the probed
            # station-id map) must survive a form save.
            return self.async_create_entry(
                title="", data={**self.config_entry.options, **user_input}
            )

        current_interval = self.config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL,
                        default=current_interval,
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL),
                    ),
                    vol.Required(
                        CONF_VOLTAGE_PUBLISH_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_VOLTAGE_PUBLISH_INTERVAL,
                            DEFAULT_VOLTAGE_PUBLISH_INTERVAL,
                        ),
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(
                            min=MIN_VOLTAGE_PUBLISH_INTERVAL,
                            max=MAX_VOLTAGE_PUBLISH_INTERVAL,
                        ),
                    ),
                    vol.Required(
                        CONF_ALERT_NOTIFICATIONS,
                        default=self.config_entry.options.get(
                            CONF_ALERT_NOTIFICATIONS, DEFAULT_ALERT_NOTIFICATIONS
                        ),
                    ): bool,
                }
            ),
        )
