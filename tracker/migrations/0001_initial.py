# Generated by Django 4.2.17 on 2025-02-03 09:46

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AllTicket',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('priority', models.CharField(max_length=255)),
                ('ticket_id', models.DecimalField(decimal_places=0, max_digits=20, unique=True)),
                ('subject', models.CharField(max_length=255)),
                ('brand_name', models.CharField(max_length=255)),
                ('requester', models.CharField(max_length=255)),
                ('group', models.CharField(max_length=255)),
                ('assignee', models.CharField(max_length=255)),
                ('last_status', models.IntegerField()),
                ('requested', models.CharField(max_length=255)),
                ('status', models.CharField(max_length=255)),
                ('aging', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Assignee',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(max_length=255, unique=True)),
                ('user_name', models.CharField(max_length=255)),
                ('group', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='AssigneeTreeView',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(max_length=255, unique=True)),
                ('user_name', models.CharField(max_length=255)),
                ('parent', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Brand',
            fields=[
                ('brand_id', models.AutoField(primary_key=True, serialize=False)),
                ('brand_name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Buttons',
            fields=[
                ('status_id', models.AutoField(primary_key=True, serialize=False)),
                ('status_name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='DashboardInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_group_head', models.BooleanField()),
            ],
        ),
        migrations.CreateModel(
            name='Files',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('filename', models.CharField(max_length=255)),
                ('file_unique_id', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Priority',
            fields=[
                ('priority_id', models.AutoField(primary_key=True, serialize=False)),
                ('priority_name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='ResetPasswordModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('new_password', models.CharField(max_length=255)),
                ('reset_code', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Ticket',
            fields=[
                ('ticket_id', models.AutoField(primary_key=True, serialize=False)),
                ('subject', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('status', models.IntegerField(choices=[(1, 'Open'), (2, 'In Progress'), (3, 'Closed')], default=1)),
                ('priority', models.CharField(choices=[('L', 'Low'), ('M', 'Medium'), ('H', 'High')], default='M', max_length=1)),
                ('brand', models.CharField(blank=True, max_length=100)),
                ('ccs', models.TextField(blank=True)),
                ('assigned_to', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_tickets', to=settings.AUTH_USER_MODEL)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_tickets', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='TicketAnalytics',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('open_tickets', models.IntegerField()),
                ('pending_tickets', models.IntegerField()),
                ('closed_tickets', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='TicketAnalyticsType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TicketDetail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('row_id', models.DecimalField(decimal_places=0, max_digits=20, unique=True)),
                ('user_id', models.CharField(max_length=255)),
                ('comment', models.TextField()),
                ('created', models.DateTimeField()),
                ('user_name', models.CharField(max_length=255)),
                ('is_internal_reply', models.BooleanField()),
            ],
        ),
        migrations.CreateModel(
            name='TicketFiles',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reference_id', models.DecimalField(decimal_places=0, max_digits=20, unique=True)),
                ('file_name', models.CharField(max_length=255)),
                ('file_unique_id', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TicketMain',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subject', models.CharField(max_length=255)),
                ('created', models.DateTimeField()),
                ('generated_by_name', models.CharField(max_length=255)),
                ('generated_by', models.CharField(max_length=255)),
                ('ticket_id', models.DecimalField(decimal_places=0, max_digits=20, unique=True)),
                ('ccs', models.TextField()),
                ('brand_id', models.IntegerField()),
                ('is_support_email', models.BooleanField()),
                ('priority_id', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='TicketReply',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ticket_to_reply', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TicketSummary',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status_id', models.IntegerField()),
                ('type', models.CharField(max_length=255)),
                ('count', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='TicketUpdateData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_status', models.CharField(max_length=255)),
                ('requester', models.CharField(max_length=255)),
                ('ccs', models.TextField()),
                ('group', models.CharField(max_length=255)),
                ('assignee', models.CharField(max_length=255)),
                ('ticket_id', models.DecimalField(decimal_places=0, max_digits=20, unique=True)),
                ('requester_name', models.CharField(max_length=255)),
                ('assignee_name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TicketUser',
            fields=[
                ('user_id', models.AutoField(primary_key=True, serialize=False)),
                ('assign_to', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TicketView',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('group_list_created', models.JSONField()),
                ('group_list_assigned', models.JSONField()),
                ('user_list_created', models.JSONField()),
                ('user_list_assigned', models.JSONField()),
            ],
        ),
        migrations.CreateModel(
            name='TreeViewMyView',
            fields=[
                ('id', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('parent', models.CharField(max_length=255)),
                ('text', models.CharField(max_length=255)),
                ('status', models.CharField(max_length=255)),
                ('level_text', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TvGroupList',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('group_id', models.DecimalField(decimal_places=0, max_digits=20, unique=True)),
                ('group_name', models.CharField(max_length=255)),
                ('count', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='TvUserListTree',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('row_id', models.DecimalField(decimal_places=0, max_digits=20, unique=True)),
                ('user_name', models.CharField(max_length=255)),
                ('group_id', models.IntegerField()),
                ('user_id', models.CharField(max_length=255)),
                ('count', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='UserDetail',
            fields=[
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('row_id', models.AutoField(primary_key=True, serialize=False)),
                ('user_id', models.CharField(max_length=255, unique=True)),
                ('user_name', models.CharField(max_length=255)),
                ('password', models.CharField(max_length=255)),
                ('role_id', models.IntegerField()),
                ('change_password', models.BooleanField(default=False)),
                ('is_email_verified', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('pagination', models.IntegerField(default=10)),
                ('brand_id', models.IntegerField(blank=True, null=True)),
                ('sorting', models.IntegerField(default=0)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='TicketSummaryAdmin',
            fields=[
                ('ticketsummary_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='tracker.ticketsummary')),
                ('user_id', models.CharField(max_length=255)),
            ],
            bases=('tracker.ticketsummary',),
        ),
        migrations.CreateModel(
            name='UserSettingsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pagination', models.IntegerField(default=10)),
                ('sorting', models.IntegerField(default=0)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tracker.userdetail')),
            ],
        ),
        migrations.CreateModel(
            name='UserResetCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reset_password_code', models.CharField(max_length=255)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tracker.userdetail')),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reset_code', models.CharField(blank=True, max_length=100)),
                ('activation_code', models.CharField(blank=True, max_length=100)),
                ('is_email_verified', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='TicketComment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('comment', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_internal', models.BooleanField(default=False)),
                ('ticket', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='tracker.ticket')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='TicketAttachment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_name', models.CharField(max_length=255)),
                ('file', models.FileField(upload_to='ticket_attachments/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('ticket', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachments', to='tracker.ticket')),
                ('uploaded_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ChangePasswordModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('old_password', models.CharField(max_length=255)),
                ('new_password', models.CharField(max_length=255)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tracker.userdetail')),
            ],
        ),
    ]
