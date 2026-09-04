"""Tests for the Whisker Ting config flow (100% of config_flow.py)."""

from dataclasses import replace

import pytest

from custom_components.whisker_ting.api import WhiskerAuthError, WhiskerConnectionError
from custom_components.whisker_ting.auth import AuthenticationError
from custom_components.whisker_ting.const import DOMAIN
from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from .const import TEST_USER_ID, TEST_USERNAME, USER_INPUT


async def test_user_success(hass: HomeAssistant, mock_client):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Whisker Ting (Ada Lovelace)"
    assert result["data"] == USER_INPUT
    assert result["result"].unique_id == str(TEST_USER_ID)


async def test_user_success_without_first_name(hass: HomeAssistant, mock_client):
    """Title falls back to the username when the API has no first name on file."""
    mock_client.get_user_data.return_value = replace(
        mock_client.get_user_data.return_value, first_name=""
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == f"Whisker Ting ({TEST_USERNAME})"


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (AuthenticationError("bad"), "invalid_auth"),
        (WhiskerAuthError("bad"), "invalid_auth"),
        (WhiskerConnectionError("down"), "cannot_connect"),
        (RuntimeError("boom"), "unknown"),
    ],
)
async def test_user_errors_recover(hass: HomeAssistant, mock_client, exc, expected):
    mock_client.get_user_data.side_effect = exc
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": expected}

    mock_client.get_user_data.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_already_configured(hass: HomeAssistant, mock_client, mock_config_entry):
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reauth_success(hass: HomeAssistant, mock_client, mock_config_entry):
    mock_config_entry.add_to_hass(hass)
    result = await mock_config_entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"

    new_input = {**USER_INPUT, "password": "newpass"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], new_input
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert mock_config_entry.data["password"] == "newpass"


async def test_reauth_wrong_account(
    hass: HomeAssistant, mock_client, mock_config_entry
):
    mock_config_entry.add_to_hass(hass)
    result = await mock_config_entry.start_reauth_flow(hass)

    other = replace(mock_client.get_user_data.return_value, user_id=99999)
    mock_client.get_user_data.return_value = other
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "wrong_account"


async def test_reauth_invalid_then_ok(
    hass: HomeAssistant, mock_client, mock_config_entry
):
    mock_config_entry.add_to_hass(hass)
    result = await mock_config_entry.start_reauth_flow(hass)

    mock_client.get_user_data.side_effect = WhiskerAuthError("bad")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["errors"] == {"base": "invalid_auth"}

    mock_client.get_user_data.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    await hass.async_block_till_done()
    assert result["reason"] == "reauth_successful"


async def test_reauth_cannot_connect(
    hass: HomeAssistant, mock_client, mock_config_entry
):
    mock_config_entry.add_to_hass(hass)
    result = await mock_config_entry.start_reauth_flow(hass)
    mock_client.get_user_data.side_effect = WhiskerConnectionError("down")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["errors"] == {"base": "cannot_connect"}


async def test_reauth_unknown(hass: HomeAssistant, mock_client, mock_config_entry):
    mock_config_entry.add_to_hass(hass)
    result = await mock_config_entry.start_reauth_flow(hass)
    mock_client.get_user_data.side_effect = RuntimeError("boom")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["errors"] == {"base": "unknown"}


async def test_options_flow(hass: HomeAssistant, mock_client, mock_config_entry):
    mock_config_entry.add_to_hass(hass)
    # Internal (non-form) options such as the probed station-id map must
    # survive a form save.
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={**mock_config_entry.options, "station_ids": {"TG-0001": "1234"}},
    )
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "scan_interval": 120,
            "voltage_publish_interval": 10,
            "alert_notifications": True,
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        "scan_interval": 120,
        "voltage_publish_interval": 10,
        "alert_notifications": True,
        "station_ids": {"TG-0001": "1234"},
    }
