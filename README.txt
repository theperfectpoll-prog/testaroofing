TESTA ROOFING — MICROSOFT GRAPH EMAIL SETUP

Place email_service.py beside app.py.

Copy .env.example as a new file named .env and enter:

MS_TENANT_ID
    Use Directory (tenant) ID.

MS_CLIENT_ID
    Use Application (client) ID.

MS_CLIENT_SECRET
    Use the client secret VALUE.

Do not use the client secret ID in .env. The secret ID may stay in your
private notes, but Flask cannot authenticate with it.

Then follow app_route_and_imports.txt and requirements_update.txt.

FIRST TEST

1. Save the files.
2. Confirm .env is beside app.py.
3. Run python app.py.
4. Open http://127.0.0.1:5000/contact.
5. Submit a test request.
6. Check brett@testaroofing.com.
7. Check Sent Items for brett@testaroofing.com.

SECURITY

Never upload .env or paste its contents into chat.
After the values are stored in .env and a secure password manager,
delete the temporary plaintext notes file.
