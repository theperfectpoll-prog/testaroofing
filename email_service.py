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
        authority=(
            f"https://login.microsoftonline.com/"
            f"{tenant_id}"
        ),
        client_credential=client_secret,
    )

    result = app.acquire_token_for_client(
        scopes=GRAPH_SCOPE
    )

    access_token = result.get("access_token")

    if not access_token:
        error = result.get(
            "error",
            "unknown_error",
        )

        description = result.get(
            "error_description",
            "Microsoft did not return an access token.",
        )

        raise EmailDeliveryError(
            f"Microsoft authentication failed: "
            f"{error}. {description}"
        )

    return access_token

def _send_email(
    recipient: str,
    subject: str,
    body_html: str,
    reply_to_name: str = "",
    reply_to_email: str = "",
) -> None:
    sender = _required_setting("MS_SENDER")

    message = {
        "subject": subject,
        "body": {
            "contentType": "HTML",
            "content": body_html,
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": recipient
                }
            }
        ],
    }

    if reply_to_email:
        message["replyTo"] = [
            {
                "emailAddress": {
                    "name": (
                        reply_to_name
                        or reply_to_email
                    ),
                    "address": reply_to_email,
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
                "Authorization": (
                    f"Bearer {_get_access_token()}"
                ),
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )

    except requests.RequestException as exc:
        raise EmailDeliveryError(
            "A network error occurred while "
            "contacting Microsoft Graph."
        ) from exc

    if response.status_code != 202:
        try:
            details = response.json()
        except ValueError:
            details = response.text

        raise EmailDeliveryError(
            "Microsoft Graph rejected the email "
            f"(HTTP {response.status_code}): "
            f"{details}"
        )

def _display(value: str) -> str:
    value = value.strip()

    return (
        html.escape(value)
        if value
        else "Not provided"
    )

def send_contact_email(
    form_data: Mapping[str, str],
) -> None:
    recipient = _required_setting("MS_RECIPIENT")

    customer_name = form_data.get(
        "name",
        "",
    ).strip()

    customer_email = form_data.get(
        "email",
        "",
    ).strip()

    state_labels = {
        "OH": "Ohio",
        "PA": "Pennsylvania",
    }

    state = form_data.get(
        "state",
        "",
    ).strip()

    state_display = state_labels.get(
        state,
        state,
    )

    body_html = f"""
    <html>
      <body
        style="
          font-family:Arial,sans-serif;
          color:#1f2933;
          line-height:1.6;
        "
      >
        <h2 style="color:#123b5d;">
          New Request for an Evaluation
        </h2>

        <table
          cellpadding="7"
          cellspacing="0"
          style="border-collapse:collapse;"
        >
          <tr>
            <td><strong>Name</strong></td>
            <td>
              {_display(form_data.get("name", ""))}
            </td>
          </tr>

          <tr>
            <td><strong>Company</strong></td>
            <td>
              {_display(form_data.get("company", ""))}
            </td>
          </tr>

          <tr>
            <td><strong>Phone</strong></td>
            <td>
              {_display(form_data.get("phone", ""))}
            </td>
          </tr>

          <tr>
            <td><strong>Email</strong></td>
            <td>{_display(customer_email)}</td>
          </tr>

          <tr>
            <td>
              <strong>Property Address</strong>
            </td>
            <td>
              {_display(
                  form_data.get(
                      "property_address",
                      "",
                  )
              )}
            </td>
          </tr>

          <tr>
            <td><strong>City</strong></td>
            <td>
              {_display(form_data.get("city", ""))}
            </td>
          </tr>

          <tr>
            <td><strong>State</strong></td>
            <td>{_display(state_display)}</td>
          </tr>

          <tr>
            <td>
              <strong>Building Type</strong>
            </td>
            <td>
              {_display(
                  form_data.get(
                      "building_type",
                      "",
                  )
              )}
            </td>
          </tr>

          <tr>
            <td>
              <strong>Service Needed</strong>
            </td>
            <td>
              {_display(
                  form_data.get(
                      "service_needed",
                      "",
                  )
              )}
            </td>
          </tr>
        </table>

        <h3
          style="
            color:#123b5d;
            margin-top:28px;
          "
        >
          How can we help?
        </h3>

        <div
          style="
            white-space:pre-wrap;
            padding:16px;
            background:#f4f7f9;
            border-radius:6px;
          "
        >
          {_display(form_data.get("message", ""))}
        </div>
      </body>
    </html>
    """.strip()

    _send_email(
        recipient=recipient,
        subject=(
            "New Evaluation Request - "
            f"{customer_name or 'Website Visitor'}"
        ),
        body_html=body_html,
        reply_to_name=customer_name,
        reply_to_email=customer_email,
    )


def send_admin_password_reset_email(
    recipient_email: str,
    first_name: str,
    reset_url: str,
) -> None:
    safe_name = html.escape(
        first_name.strip()
        or "Administrator"
    )

    safe_reset_url = html.escape(
        reset_url,
        quote=True,
    )

    body_html = f"""
    <html>
      <body
        style="
          font-family:Arial,sans-serif;
          color:#1f2933;
          line-height:1.6;
        "
      >
        <h2 style="color:#123b5d;">
          Reset Your Testa Roofing Password
        </h2>

        <p>
          Hello {safe_name},
        </p>

        <p>
          A password reset was requested for
          your Testa Roofing administrator account.
        </p>

        <p>
          This link will expire in
          <strong>15 minutes</strong>.
        </p>

        <p style="margin:28px 0;">
          <a
            href="{safe_reset_url}"
            style="
              background:#123b5d;
              color:#ffffff;
              text-decoration:none;
              padding:12px 20px;
              border-radius:5px;
              display:inline-block;
              font-weight:bold;
            "
          >
            Reset Password
          </a>
        </p>

        <p>
          If you did not request this reset,
          you can ignore this email. Your
          current password has not been changed.
        </p>

        <p>
          For security, do not forward this
          email or share the reset link.
        </p>

        <p>
          Testa Roofing
        </p>
      </body>
    </html>
    """.strip()

    _send_email(
        recipient=recipient_email,
        subject=(
            "Testa Roofing Administrator "
            "Password Reset"
        ),
        body_html=body_html,
    )


def send_admin_password_changed_email(
    recipient_email: str,
    first_name: str,
) -> None:
    safe_name = html.escape(
        first_name.strip()
        or "Administrator"
    )

    body_html = f"""
    <html>
      <body
        style="
          font-family:Arial,sans-serif;
          color:#1f2933;
          line-height:1.6;
        "
      >
        <h2 style="color:#123b5d;">
          Your Administrator Password Was Changed
        </h2>

        <p>
          Hello {safe_name},
        </p>

        <p>
          The password for your Testa Roofing
          administrator account was successfully
          changed.
        </p>

        <p>
          If you made this change, no further
          action is needed.
        </p>

        <p>
          If you did not make this change,
          contact the Testa Roofing system owner
          immediately.
        </p>

        <p>
          Testa Roofing
        </p>
      </body>
    </html>
    """.strip()

    _send_email(
        recipient=recipient_email,
        subject=(
            "Security Notice: Testa Roofing "
            "Administrator Password Changed"
        ),
        body_html=body_html,
    )

def send_admin_invitation_email(
    recipient_email: str,
    first_name: str,
    inviter_name: str,
    invitation_url: str,
) -> None:
    safe_name = html.escape(
        first_name.strip()
        or "Administrator"
    )

    safe_inviter_name = html.escape(
        inviter_name.strip()
        or "the Testa Roofing system owner"
    )

    safe_invitation_url = html.escape(
        invitation_url,
        quote=True,
    )

    body_html = f"""
    <html>
      <body
        style="
          font-family:Arial,sans-serif;
          color:#1f2933;
          line-height:1.6;
        "
      >
        <h2 style="color:#123b5d;">
          Testa Roofing Administrator Invitation
        </h2>

        <p>
          Hello {safe_name},
        </p>

        <p>
          {safe_inviter_name} invited you to create
          a Testa Roofing administrator account.
        </p>

        <p>
          This secure invitation link will expire
          in <strong>24 hours</strong>.
        </p>

        <p style="margin:28px 0;">
          <a
            href="{safe_invitation_url}"
            style="
              background:#123b5d;
              color:#ffffff;
              text-decoration:none;
              padding:12px 20px;
              border-radius:5px;
              display:inline-block;
              font-weight:bold;
            "
          >
            Create Administrator Account
          </a>
        </p>

        <p>
          You will be asked to create a password
          containing at least 16 characters.
        </p>

        <p>
          If you were not expecting this invitation,
          do not use or forward this email.
        </p>

        <p>
          Testa Roofing
        </p>
      </body>
    </html>
    """.strip()

    _send_email(
        recipient=recipient_email,
        subject=(
            "Testa Roofing Administrator Invitation"
        ),
        body_html=body_html,
    )