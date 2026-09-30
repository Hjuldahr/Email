import smtplib

with smtplib.SMTP("127.0.0.1", 1025) as smtp:
    smtp.sendmail(
        "alice@example.com",
        ["bob@example.com"],
        """From: alice@example.com
To: bob@example.com
Subject: Test message

Hello from my prototype SMTP server!
""",
    )