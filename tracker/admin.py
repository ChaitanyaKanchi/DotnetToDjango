from django.contrib import admin
from .models import (
    Role,
    UserDetail,
    Ticket,
    TicketComment,
    TicketAttachment,
    UserProfile,
    UserSettingsModel
)

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name',)

@admin.register(UserDetail)
class UserDetailAdmin(admin.ModelAdmin):
    list_display = ('user_id', 'user_name', 'role', 'department', 'is_active')
    list_filter = ('role', 'is_active', 'department')
    search_fields = ('user_id', 'user_name', 'department')
    ordering = ('user_id',)

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('id', 'subject', 'created_by', 'assigned_to', 'status', 'priority', 'created_at')
    list_filter = ('status', 'priority', 'created_at')
    search_fields = ('subject', 'description')
    date_hierarchy = 'created_at'

@admin.register(TicketComment)
class TicketCommentAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'user', 'created_at', 'is_internal')
    list_filter = ('is_internal', 'created_at')
    search_fields = ('comment',)

@admin.register(TicketAttachment)
class TicketAttachmentAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'file_name', 'uploaded_by', 'uploaded_at')
    list_filter = ('uploaded_at',)
    search_fields = ('file_name',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_email_verified')
    list_filter = ('is_email_verified',)
    search_fields = ('user__email',)

@admin.register(UserSettingsModel)
class UserSettingsAdmin(admin.ModelAdmin):
    list_display = ('user', 'pagination', 'sorting')
    search_fields = ('user__email',)
