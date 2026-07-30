import html
import os
from typing import Mapping

import msal
import requests


GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


class EmailConfigurationError(RuntimeError):
    pass


class EmailDeliveryError(RuntimeError):
    pass


def _required_setting(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise EmailConfigurationError(
            f"Missing required environment variable: {name}"
        )
    return value


def _get_access_token() -> str:
    tenant_id = _required_setting("MS_TENANT_ID")
    client_id = _required_setting("MS_CLIENT_ID")
    client_secret = _required_setting("MS_CLIENT_SECRET")

    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )

    result = app.acquire_token_for_client(
        scopes=GRAPH_SCOPE
    )

    access_token = result.get("access_token")
    if not access_token:
        error = result.get("error", "unknown_error")
        description = result.get(
            "error_description",
            "Microsoft did not return an access token.",
        )
        raise EmailDeliveryError(
            f"Microsoft authentication failed: {error}. {description}"
        )

    return access_token


def _display(value: str) -> str:
    value = value.strip()
    return html.escape(value) if value else "Not provided"


def send_contact_email(form_data: Mapping[str, str]) -> None:
    sender = _required_setting("MS_SENDER")
    recipient = _required_setting("MS_RECIPIENT")

    customer_name = form_data.get("name", "").strip()
    customer_email = form_data.get("email", "").strip()

    state_labels = {"OH": "Ohio", "PA": "Pennsylvania"}
    state = form_data.get("state", "").strip()
    state_display = state_labels.get(state, state)

    body_html = f"""
    <html>
      <body style="font-family:Arial,sans-serif;color:#1f2933;line-height:1.6;">
        <h2 style="color:#123b5d;">New Request for an Evaluation</h2>
        <table cellpadding="7" cellspacing="0" style="border-collapse:collapse;">
          <tr><td><strong>Name</strong></td><td>{_display(form_data.get("name", ""))}</td></tr>
          <tr><td><strong>Company</strong></td><td>{_display(form_data.get("company", ""))}</td></tr>
          <tr><td><strong>Phone</strong></td><td>{_display(form_data.get("phone", ""))}</td></tr>
          <tr><td><strong>Email</strong></td><td>{_display(customer_email)}</td></tr>
          <tr><td><strong>Property Address</strong></td><td>{_display(form_data.get("property_address", ""))}</td></tr>
          <tr><td><strong>City</strong></td><td>{_display(form_data.get("city", ""))}</td></tr>
          <tr><td><strong>State</strong></td><td>{_display(state_display)}</td></tr>
          <tr><td><strong>Building Type</strong></td><td>{_display(form_data.get("building_type", ""))}</td></tr>
          <tr><td><strong>Service Needed</strong></td><td>{_display(form_data.get("service_needed", ""))}</td></tr>
        </table>

        <h3 style="color:#123b5d;margin-top:28px;">How can we help?</h3>
        <div style="white-space:pre-wrap;padding:16px;background:#f4f7f9;border-radius:6px;">{_display(form_data.get("message", ""))}</div>
      </body>
    </html>
    """.strip()

    message = {
        "subject": f"New Evaluation Request - {customer_name or 'Website Visitor'}",
        "body": {
            "contentType": "HTML",
            "content": body_html,
        },
        "toRecipients": [
            {"emailAddress": {"address": recipient}}
        ],
    }

    if customer_email:
        message["replyTo"] = [
            {
                "emailAddress": {
                    "name": customer_name or customer_email,
                    "address": customer_email,
                }
            }
        ]

    payload = {
        "message": message,
        "saveToSentItems": True,
    }

    try:
        response = requests.post(
            f"{GRAPH_BASE_URL}/users/{sender}/sendMail",
            headers={
                "Authorization": f"Bearer {_get_access_token()}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
    except requests.RequestException as exc:
        raise EmailDeliveryError(
            "A network error occurred while contacting Microsoft Graph."
        ) from exc

    if response.status_code != 202:
        try:
            details = response.json()
        except ValueError:
            details = response.text

        raise EmailDeliveryError(
            f"Microsoft Graph rejected the email "
            f"(HTTP {response.status_code}): {details}"
        )
