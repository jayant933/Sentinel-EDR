"""
email_config.example.py
-------------------------
Copy this file to `email_config.py` (same folder) and fill in your
details to enable email alerts. `email_config.py` is gitignored so
your credentials never get committed.

GMAIL SETUP (recommended, free):
1. Turn on 2-Step Verification on your Google account:
   https://myaccount.google.com/security
2. Create an "App Password":
   https://myaccount.google.com/apppasswords
   - App: "Mail", Device: "Other" (name it "SENTINEL EDR")
   - Google gives you a 16-character password - use THAT below,
     not your normal Gmail password.
3. Fill in the values below and rename this file to email_config.py
"""

EMAIL_ENABLED = False  # set to True once you've filled in the fields below

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

SENDER_EMAIL = "youraddress@gmail.com"
SENDER_APP_PASSWORD = "xxxx xxxx xxxx xxxx"  # the 16-char App Password, not your real password

RECIPIENT_EMAIL = "youraddress@gmail.com"  # can be the same as sender, or a different address