import json
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import BaseUserManager
from django.contrib.postgres.fields import ArrayField
from django.core.serializers.json import DjangoJSONEncoder




class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("username", email)  # Set username to email

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    
    # Define choices for user roles
    ROLE_CHOICES = [
        ('superadmin', 'SuperAdmin'),
        ('admin', 'Admin'),
        ('editor', 'Editor'),
        ('reader', 'Reader'),
        ('member', 'Member'),
        ('domain-admin', 'Domain Admin'),
    ]

    ACCOUNT_STATUS = [
        ('pending', 'Pending'),
        ('suspended', 'Suspended'),
        ('active', 'Active'),
    ]

    RANKUP_CHOICES = [
        ('epb', 'EPB'),
        ('opb', 'OPB')
    ]

    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255,blank=True, null=True)
    phone = models.CharField(max_length=20, default='')

    is_phone_verified = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    state = models.CharField(max_length=2, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    fcm = models.CharField(max_length=255, blank=True, null=True)

    zip_code = models.CharField(max_length=10, blank=True, null=True)
    profile_pic = models.ImageField(
        upload_to='profile_pics/', blank=True, null=True)

    email = models.EmailField(unique=True)
    role = models.CharField(
        max_length=13, choices=ROLE_CHOICES, default="superadmin")
    account_status = models.CharField(blank=True, null=True,
                                      choices=ACCOUNT_STATUS, max_length=10)
    
    is_member = models.BooleanField(default=False)

    invited_by = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.SET_NULL)

    is_2fa_enabled = models.BooleanField(default=False)
    is_2fa_authenticator_enabled = models.BooleanField(default=False)
    is_2fa_sms_enabled = models.BooleanField(default=False)
    is_2fa_email_enabled = models.BooleanField(default=False)
    totp_key = models.CharField(max_length=32, blank=True)

    date_invite_sent = models.DateTimeField(null=True, blank=True)
    stripe_customer_id = models.CharField(max_length=255, blank=True)

    # Boolean Fields for notification preferences
    is_alert_notifications = models.BooleanField(default=False)
    is_polls = models.BooleanField(default=False)
    is_templates = models.BooleanField(default=False)
    is_schedule = models.BooleanField(default=False)
    is_groups = models.BooleanField(default=False)
    is_emergencies = models.BooleanField(default=False)
    is_email_notifications = models.BooleanField(default=False)
    is_billing_alert = models.BooleanField(default=False)
    is_newsletter = models.BooleanField(default=False)

    # feature preferences
    alert = models.CharField(max_length=255, blank=True)
    polls = models.CharField(max_length=255, blank=True)
    schedule = models.CharField(max_length=255, blank=True)
    template = models.CharField(max_length=255, blank=True)

    # hotbutton
    code = models.CharField(max_length=6, blank=True, null=True)
    fcm = models.CharField(max_length=510, blank=True, null=True)
    
    #sso
    google_id = models.CharField(blank=True, null=True)
    facebook_id = models.CharField(blank=True, null=True)
    apple_id = models.CharField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    class Meta:
        ordering = 'id',

