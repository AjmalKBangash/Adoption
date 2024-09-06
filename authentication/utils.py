from django.core.mail import send_mail
from django.conf import settings
import random
from .models import Otps
from celery import shared_task

class UserActivation():
    @staticmethod
    @shared_task
    def sending_mail(email):
        random_number = random.randint(1000, 9999)

        # Using get_or_create to either get the existing instance or create a new one
        otp_instance, created = Otps.objects.get_or_create(user_email=email)
        
        # Update the OTP value in any case
        otp_instance.user_otp = str(random_number)
        otp_instance.save()

        # SENDING EMAIL
        subject = "Your Account Email!"
        body = "Here is the your OTP from Murakiba Administration" + " " + str(random_number)
        email_from = settings.EMAIL_HOST_USER
        email_to = email

        try:
            send_mail(
                subject,
                body,
                email_from,
                [email_to],
                fail_silently=False,
            )
            print("Email sent successfully!")
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            # return f"Error sending email: {e}"
            return False
