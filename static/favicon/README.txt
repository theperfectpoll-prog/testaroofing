TESTA ROOFING FAVICON PACKAGE

1. Create this folder in your Flask project:
   static/favicon/

2. Copy every file from this package into:
   static/favicon/

3. Add the following lines inside the <head> section of templates/base.html:

<link rel="icon" type="image/x-icon" href="{{ url_for('static', filename='favicon/favicon.ico') }}">
<link rel="icon" type="image/png" sizes="32x32" href="{{ url_for('static', filename='favicon/favicon-32x32.png') }}">
<link rel="icon" type="image/png" sizes="16x16" href="{{ url_for('static', filename='favicon/favicon-16x16.png') }}">
<link rel="apple-touch-icon" sizes="180x180" href="{{ url_for('static', filename='favicon/apple-touch-icon.png') }}">
<link rel="manifest" href="{{ url_for('static', filename='favicon/site.webmanifest') }}">
<meta name="theme-color" content="#173d5b">

4. Save base.html and restart Flask.

5. Browser favicon caching can be stubborn. After restarting:
   - Open the site in a private/incognito window, or
   - Hard-refresh with Ctrl+F5, or
   - Clear cached images/files for localhost.

Generated files:
- favicon.ico
- favicon-16x16.png
- favicon-32x32.png
- apple-touch-icon.png
- android-chrome-192x192.png
- android-chrome-512x512.png
- site.webmanifest
