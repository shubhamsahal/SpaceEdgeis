import smtplib
import random
from email.mime.text import MIMEText

# Store OTPs temporarily (use DB in production)
otp_storage = {}

def send_otp_email(receiver_email):
    try:
        otp = str(random.randint(100000, 999999))  # Generate 6-digit OTP

        # Gmail settings
        sender_email = "ss27298194@gmail.com"
        app_password = "ixbt htiw plhc wrjb"  # <-- Replace with Gmail App Password

        # Email content
        msg = MIMEText(f"Your OTP for Space Edge is: {otp}")
        msg["Subject"] = "Space Edge - Email Verification OTP"
        msg["From"] = sender_email
        msg["To"] = receiver_email

        # Connect to Gmail SMTP
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()

        # Save OTP temporarily
        otp_storage[receiver_email] = otp
        print(f"✅ OTP sent to {receiver_email}: {otp}")

        # 👉 Return the actual OTP (string)
        return otp

    except Exception as e:
        print("❌ Error sending OTP:", e)
        return None


def verify_otp_email_code(receiver_email, otp_code):
    """Check if entered OTP matches"""
    return otp_storage.get(receiver_email) == otp_code
