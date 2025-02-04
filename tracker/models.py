# Create your models here.
from datetime import timedelta
from django.db import models
from django.utils.timezone import now
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, User

# From Here Login App Models

# User Manager for Custom User Model
class UserManager(BaseUserManager):
    def create_user(self, user_id, user_name, password, role_id, **extra_fields):
        if not user_id:
            raise ValueError("User ID is required")
        user = self.model(
            user_id=user_id,
            user_name=user_name,
            role_id=role_id,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, user_id, user_name, password, role_id, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(user_id, user_name, password, role_id, **extra_fields)

# User Model
class UserDetail(AbstractBaseUser, PermissionsMixin):
    row_id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=255, unique=True)
    user_name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    role_id = models.IntegerField()
    change_password = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    pagination = models.IntegerField(default=10)
    brand_id = models.IntegerField(null=True, blank=True)
    sorting = models.IntegerField(default=0)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    objects = UserManager()

    USERNAME_FIELD = "user_id"
    REQUIRED_FIELDS = ["user_name", "role_id"]

    def __str__(self):
        return self.user_name

    class Meta:
        swappable = 'AUTH_USER_MODEL'

# User Reset Code Model
class UserResetCode(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reset_codes'
    )
    reset_password_code = models.CharField(max_length=255)

    def __str__(self):
        return f"Reset Code for {self.user.user_id}"

# Reset Password Model
class ResetPasswordModel(models.Model):
    new_password = models.CharField(max_length=255)
    reset_code = models.CharField(max_length=255)


class PasswordResetToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_reset_tokens'
    )
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        expiration_time = self.created_at + timedelta(hours=24)
        return now() > expiration_time

    def __str__(self):
        return f"Password Reset Token for {self.user.user_id}"


# Change Password Model
class ChangePasswordModel(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_changes'
    )
    old_password = models.CharField(max_length=255)
    new_password = models.CharField(max_length=255)

# User Settings Model
class UserSettingsModel(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_settings'
    )
    pagination = models.IntegerField(default=10)
    sorting = models.IntegerField(default=0)

    def __str__(self):
        return f"Settings for {self.user.user_id}"

    class Meta:
        db_table = 'user_settings'

# From here Tickets App Models

class Assignee(models.Model):
    user_id = models.CharField(max_length=255, unique=True)
    user_name = models.CharField(max_length=255)
    group = models.CharField(max_length=255)

class AssigneeTreeView(models.Model):
    user_id = models.CharField(max_length=255, unique=True)
    user_name = models.CharField(max_length=255)
    parent = models.CharField(max_length=255)

class Priority(models.Model):
    priority_id = models.AutoField(primary_key=True)
    priority_name = models.CharField(max_length=255)

class Brand(models.Model):
    brand_id = models.AutoField(primary_key=True)
    brand_name = models.CharField(max_length=255)

class Buttons(models.Model):
    status_id = models.AutoField(primary_key=True)
    status_name = models.CharField(max_length=255)

class TicketUser(models.Model):
    user_id = models.AutoField(primary_key=True)
    assign_to = models.CharField(max_length=255)

class AllTicket(models.Model):
    priority = models.CharField(max_length=255)
    ticket_id = models.DecimalField(max_digits=20, decimal_places=0, unique=True)
    subject = models.CharField(max_length=255)
    brand_name = models.CharField(max_length=255)
    requester = models.CharField(max_length=255)
    group = models.CharField(max_length=255)
    assignee = models.CharField(max_length=255)
    last_status = models.IntegerField()
    requested = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    aging = models.CharField(max_length=255)

class TicketAnalytics(models.Model):
    name = models.CharField(max_length=255)
    open_tickets = models.IntegerField()
    pending_tickets = models.IntegerField()
    closed_tickets = models.IntegerField()

class TicketAnalyticsType(models.Model):
    name = models.CharField(max_length=255)

class DashboardInfo(models.Model):
    is_group_head = models.BooleanField()

class TicketSummary(models.Model):
    status_id = models.IntegerField()
    type = models.CharField(max_length=255)
    count = models.IntegerField()

class TicketSummaryAdmin(TicketSummary):
    user_id = models.CharField(max_length=255)

class TicketMain(models.Model):
    subject = models.CharField(max_length=255)
    created = models.DateTimeField()
    generated_by_name = models.CharField(max_length=255)
    generated_by = models.CharField(max_length=255)
    ticket_id = models.DecimalField(max_digits=20, decimal_places=0, unique=True)
    ccs = models.TextField()
    brand_id = models.IntegerField()
    is_support_email = models.BooleanField()
    priority_id = models.IntegerField()

class TicketDetail(models.Model):
    row_id = models.DecimalField(max_digits=20, decimal_places=0, unique=True)
    user_id = models.CharField(max_length=255)
    comment = models.TextField()
    created = models.DateTimeField()
    user_name = models.CharField(max_length=255)
    is_internal_reply = models.BooleanField()

class TicketFiles(models.Model):
    reference_id = models.DecimalField(max_digits=20, decimal_places=0, unique=True)
    file_name = models.CharField(max_length=255)
    file_unique_id = models.CharField(max_length=255)

class TicketReply(models.Model):
    ticket_to_reply = models.CharField(max_length=255)

class Files(models.Model):
    filename = models.CharField(max_length=255)
    file_unique_id = models.CharField(max_length=255)

class TicketUpdateData(models.Model):
    last_status = models.CharField(max_length=255)
    requester = models.CharField(max_length=255)
    ccs = models.TextField()
    group = models.CharField(max_length=255)
    assignee = models.CharField(max_length=255)
    ticket_id = models.DecimalField(max_digits=20, decimal_places=0, unique=True)
    requester_name = models.CharField(max_length=255)
    assignee_name = models.CharField(max_length=255)

class TreeViewMyView(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    parent = models.CharField(max_length=255)
    text = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    level_text = models.CharField(max_length=255)

class TicketView(models.Model):
    group_list_created = models.JSONField()
    group_list_assigned = models.JSONField()
    user_list_created = models.JSONField()
    user_list_assigned = models.JSONField()

class TvGroupList(models.Model):
    group_id = models.DecimalField(max_digits=20, decimal_places=0, unique=True)
    group_name = models.CharField(max_length=255)
    count = models.IntegerField()

class TvUserListTree(models.Model):
    row_id = models.DecimalField(max_digits=20, decimal_places=0, unique=True)
    user_name = models.CharField(max_length=255)
    group_id = models.IntegerField()
    user_id = models.CharField(max_length=255)
    count = models.IntegerField()

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    reset_code = models.CharField(max_length=100, blank=True)
    activation_code = models.CharField(max_length=100, blank=True)
    is_email_verified = models.BooleanField(default=False)

class Ticket(models.Model):
    STATUS_CHOICES = [
        (1, 'New'),
        (2, 'In Progress'),
        (3, 'Pending'),
        (4, 'Resolved'),
        (5, 'Closed'),
    ]
    
    PRIORITY_CHOICES = (
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical')
    )

    id = models.AutoField(primary_key=True)  # Changed from ticket_id
    subject = models.CharField(max_length=200)
    description = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_tickets')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_tickets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.IntegerField(choices=STATUS_CHOICES, default=1)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='Medium')
    brand = models.CharField(max_length=100, blank=True)
    ccs = models.TextField(blank=True)

class TicketComment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_internal = models.BooleanField(default=False)

class TicketAttachment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='attachments')
    file_name = models.CharField(max_length=255)
    file = models.FileField(upload_to='ticket_attachments/')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
