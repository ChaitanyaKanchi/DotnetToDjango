# Create your views here.

# this are HomeControl views

from email.message import EmailMessage
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.urls import reverse
import uuid
from django.http import JsonResponse
from django.db import connection
import json
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import jwt
from .models import PasswordResetToken, Ticket, UserProfile
from .decorators import login_required_with_message, role_required, superuser_required
from django.views.generic import TemplateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from django.utils.decorators import method_decorator
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.contrib.auth import get_user_model
from .models import UserSettingsModel
from .utils import generate_password_reset_token, verify_password_reset_token
import re
from datetime import datetime, timedelta
from django.core.mail import EmailMessage
from .models import UserDetail  # Import your custom user model

User = get_user_model()

def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            # Ensure UserProfile exists
            UserProfile.objects.get_or_create(user=user)
            
            login(request, user)
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid email or password.")
    
    return render(request, "registration/login.html")  

def logout_view(request):
    logout(request)
    return redirect("login")

@login_required_with_message
def dashboard(request):
    tickets = Ticket.objects.filter(assigned_to=request.user)
    return render(request, "dashboard/index.html", {"tickets": tickets})


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email').strip()
        
        try:
            user = User.objects.filter(email__iexact=email).first()
            if user:
                # Generate reset token
                token = generate_reset_token(email)
                reset_link = request.build_absolute_uri(
                    reverse('reset_password') + f'?token={token}'

                )
                
                # Send reset email
                html_message = render_to_string('registration/email/reset_password_email.html', {
                'reset_link': reset_link
                })
                
                email = EmailMessage(
                    'Password Reset Instructions',
                    html_message,
                    settings.EMAIL_HOST_USER,
                    [user.email]
                )
                email.content_subtype = "html"
                email.send(fail_silently=False)
                
                messages.success(request, 'Password reset instructions have been sent to your email.')
                return redirect('login')
            
            messages.error(request, 'No account found with this email address.')
            
        except Exception as e:
            messages.error(request, 'An error occurred. Please try again.')
            
    return render(request, 'registration/forgot_password.html')


def generate_reset_token(email):
    """Generate JWT token for password reset"""
    exp_time = datetime.utcnow() + timedelta(minutes=30)
    return jwt.encode(
        {'email': email, 'exp': exp_time},
        settings.SECRET_KEY,
        algorithm='HS256'
    )

def verify_reset_token(token):
    """Verify JWT token validity"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def reset_password(request):
    """Handle password reset"""
    # Get token from either GET params or POST data
    token = request.GET.get('token') or request.POST.get('token')
    
    if not token:
        messages.error(request, 'Invalid reset link.')
        return redirect('login')

    # Verify token and get email
    email = verify_reset_token(token)
    if not email:
        messages.error(request, 'Invalid or expired reset link. Please request a new one.')
        return redirect('forgot_password')

    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'registration/reset_password.html', {'token': token})
            
        if not validate_password(password):
            messages.error(request, 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.')
            return render(request, 'registration/reset_password.html', {'token': token})
            
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password has been reset successfully. Please login with your new password.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('forgot_password')
    
    # For GET request, render the reset password form
    return render(request, 'registration/reset_password.html', {
        'token': token,
        'email': email,
    })

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True


# def reset_password(request, token):
#     user = verify_password_reset_token(token)
#     if not user:
#         messages.error(request, "Invalid or expired password reset link.")
#         return redirect("login")
    
#     if request.method == "POST":
#         new_password = request.POST.get("new_password")
#         confirm_password = request.POST.get("confirm_password")
        
#         if new_password != confirm_password:
#             messages.error(request, "Passwords do not match.")
#         else:
#             user.set_password(new_password)
#             user.save()
#             # Delete the used token
#             PasswordResetToken.objects.filter(user=user).delete()
#             messages.success(request, "Password has been reset successfully. Please login with your new password.")
#             return redirect("login")
    
#     return render(request, "registration/reset_password.html", {"token": token})

@login_required_with_message
def change_password(request):
    if request.method == "POST":
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")
        
        if not old_password or not new_password or not confirm_password:
            messages.error(request, "All fields are required.")
            return redirect("change_password")
            
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect("change_password")
            
        if len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return redirect("change_password")
            
        if not request.user.check_password(old_password):
            messages.error(request, "Current password is incorrect.")
            return redirect("change_password")
            
        request.user.set_password(new_password)
        request.user.save()
        messages.success(request, "Password changed successfully. Please login again.")
        return redirect("login")
    
    return render(request, "registration/change_password.html")  # Verify this path

def verify_account(request, activation_code):
    try:
        user = User.objects.get(profile__activation_code=activation_code)
        user.profile.is_email_verified = True
        user.profile.activation_code = ""
        user.profile.save()
        messages.success(request, "Account successfully verified.")
    except User.DoesNotExist:
        messages.error(request, "Invalid or expired activation link.")
    return redirect("login")

def new_account(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        
        # Validate inputs
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Please enter a valid email address.")
            return render(request, "registration/new_account.html")
            
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "registration/new_account.html")
            
        if User.objects.filter(email=email).exists():
            messages.error(request, "Account with this email already exists.")
            return render(request, "registration/new_account.html")

        # Create new user
        try:
            user = User.objects.create_user(
                username=email,
                email=email,
                password=password
            )
            
            # Generate activation code
            activation_code = str(uuid.uuid4())
            user.profile.activation_code = activation_code
            user.profile.save()
            
            # Send activation email
            activation_link = request.build_absolute_uri(
                reverse('verify_account', args=[activation_code])
            )
            send_mail(
                "Activate Your Account",
                f"Click the link below to activate your account: {activation_link}",
                "noreply@example.com",
                [email],
            )
            
            messages.success(request, "Account created successfully. Please check your email to activate your account.")
            return redirect("login")
            
        except Exception as e:
            messages.error(request, "Error creating account. Please try again.")
            return render(request, "registration/new_account.html")
            
    return render(request, "registration/new_account.html")


#  this are Tcikets control views
@login_required_with_message
def new_ticket(request):
    return render(request, "tickets/new_ticket.html")

@login_required_with_message
def all_tickets(request):
    with connection.cursor() as cursor:
        cursor.execute("EXEC dbo._sp_select_dashboardTicket", [request.user.id])
        results = dictfetchall(cursor)
    return JsonResponse(results, safe=False)

@login_required_with_message
def advanced_search(request):
    search_query = request.GET.get("search", "")
    search_level = request.GET.get("searchLevel", "")
    with connection.cursor() as cursor:
        cursor.execute("EXEC dbo._sp_search_Ticket %s, %s, %s", [search_query, request.user.id, search_level])
        results = dictfetchall(cursor)
    return JsonResponse(results, safe=False)

@role_required([1, 2])  # Allow roles 1 and 2
def view_ticket(request, ticket_id):
    return render(request, "tickets/view_ticket.html", {"ticket_id": ticket_id})

@login_required_with_message
def view_ticket_detail(request, ticket_id):
    with connection.cursor() as cursor:
        cursor.execute("EXEC dbo._sp_select_ticket_by_ticketid %s", [ticket_id])
        results = dictfetchall(cursor)
    return JsonResponse(results, safe=False)

@login_required_with_message
def save_ticket(request):
    if request.method == "POST":
        data = json.loads(request.body)
        ticket_id = data.get("ticket_id")
        assignee = data.get("assignee")
        comment = data.get("comment")
        last_status = data.get("last_status")
        subject = data.get("subject")
        brand = data.get("brand")
        attached_files = data.get("attached_files")
        ccs = data.get("ccs")
        priority = data.get("priority")

        with connection.cursor() as cursor:
            cursor.execute("EXEC dbo._sp_InsertTicket %s, %s, %s, %s, %s, %s, %s, %s, %s", 
                           [ticket_id, request.user.id, assignee, last_status, comment, subject, attached_files, brand, priority])
        
        return JsonResponse({"result": "Redirect", "url": "/dashboard"})

@login_required_with_message
def update_ticket(request):
    if request.method == "POST":
        data = json.loads(request.body)
        ticket_id = data.get("ticket_id")
        assignee = data.get("assignee")
        comment = data.get("comment")
        last_status = data.get("last_status")
        subject = data.get("subject")
        attached_files = data.get("attached_files")
        ccs = data.get("ccs")
        reply_type = data.get("reply_type")
        priority = data.get("priority")

        with connection.cursor() as cursor:
            cursor.execute("EXEC dbo._sp_UpdateTicket %s, %s, %s, %s, %s, %s, %s, %s, %s", 
                           [ticket_id, request.user.id, assignee, last_status, comment, subject, attached_files, ccs, priority])
        
        return JsonResponse({"result": "Redirect", "url": "/dashboard"})

@login_required_with_message
def user_settings(request):
    # Get or create user settings
    settings, created = UserSettingsModel.objects.get_or_create(
        user=request.user,
        defaults={'pagination': 10, 'sorting': 0}
    )

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            settings.pagination = int(data.get("pagination", 10))
            settings.sorting = int(data.get("sorting", 0))
            settings.save()
            
            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({
                "status": "error", 
                "message": str(e)
            }, status=400)
    
    # Handle GET request
    context = {
        'settings': {
            'pagination': settings.pagination,
            'sorting': settings.sorting
        }
    }
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse(context['settings'])
    
    return render(request, "registration/user_settings.html", context)

def dictfetchone(cursor):
    row = cursor.fetchone()
    if not row:
        return {"pagination": 10, "sorting": 0}  # Default values
    columns = [col[0] for col in cursor.description]
    return dict(zip(columns, row))

def dictfetchone(cursor):
    row = cursor.fetchone()
    if not row:
        return {}
    columns = [col[0] for col in cursor.description]
    return dict(zip(columns, row))

def dictfetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


# this are Ticketsmloyal views



def index(request):
    return render(request, "index.html")

@login_required_with_message
def mloyal_dashboard(request):
    return render(request, "mloyal_dashboard.html")

@login_required_with_message
def mloyal_view_ticket(request, ticket_id):
    return render(request, "mloyal_view_ticket.html", {"ticket_id": ticket_id})

@login_required_with_message
def view_ticket_detail(request, ticket_id):
    with connection.cursor() as cursor:
        cursor.execute("EXEC dbo._sp_select_ticket_by_ticketid %s", [ticket_id])
        results = dictfetchall(cursor)
    return JsonResponse(results, safe=False)

def dictfetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

# this are ticket super user views

class TicketSuperUserView(View):
    @method_decorator(superuser_required)
    def get(self, request):
        return render(request, "ticketsuperuser/home.html")

class AdminNewTicketView(View):
    def get(self, request):
        return render(request, "ticketsuperuser/admin_new_ticket.html")

class TicketDashboardView(View):
    def get(self, request, id=None, filtertype="", days="", vtype="", ticketno=""):
        nodes = []
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT g.group_id, g.group_name, COUNT(mt.assigned_to) AS Count
                FROM mst_group g
                LEFT JOIN mst_user u ON g.group_id = u.group_id
                LEFT JOIN mst_ticket mt ON mt.assigned_to = u.user_id AND mt.last_status=1
                WHERE g.group_id NOT IN (1) AND g.status_flag = 1
                GROUP BY g.group_id, g.group_name
                ORDER BY g.group_name ASC
            """)
            groups = cursor.fetchall()

        for group in groups:
            nodes.append({"id": group[0], "parent": "#", "text": f"{group[1]} ({group[2]})"})
        
        return render(request, "ticketsuperuser/ticket_dashboard.html", {"nodes": json.dumps(nodes)})

class ViewTicketView(View):
    def get(self, request, ticketid):
        return render(request, "ticketsuperuser/view_ticket.html", {"ticketid": ticketid})

class TicketDataView(View):
    def post(self, request):
        user_id = request.session.get("UserID", "")
        with connection.cursor() as cursor:
            cursor.callproc("_sp_select_TicketData_admin", [user_id])
            results = cursor.fetchall()
        
        return JsonResponse(results, safe=False)

class SaveTicketView(View):
    def post(self, request):
        data = json.loads(request.body)
        ticket_id = data.get("ticket_id")
        assignee = data.get("assignee")
        comment = data.get("comment")
        last_status = data.get("laststatus")
        subject = data.get("subject")
        brand = data.get("brand")
        ccs = data.get("ccs")
        priority = data.get("priority")
        user_id = request.session.get("UserID", "")

        with connection.cursor() as cursor:
            cursor.callproc("_sp_InsertTicket", [
                ticket_id, user_id, assignee, last_status, comment, subject, brand, ccs, priority
            ])
            results = cursor.fetchall()
        
        return JsonResponse({"Success": True, "Newticketno": results[0][0]})

class AllTicketsView(View):
    def get(self, request, user_id):
        sorting = request.session.get("Settings", "").split('$')[1]
        with connection.cursor() as cursor:
            cursor.callproc("_sp_select_dashboardTicket", [user_id, sorting])
            results = cursor.fetchall()
        
        return JsonResponse(results, safe=False)



def update_ticket_template(request):
    """Render the update ticket email template"""
    context = {
        'ticketno': request.GET.get('ticketno'),
        'user_name': request.GET.get('user_name'),
        'created': request.GET.get('created'),
        'comment': request.GET.get('comment'),
        # ...other context variables...
    }
    return render(request, 'template/updateticket.html', context)

def ticket_email_template(request):
    """Render the ticket by email template"""
    context = {
        'ticketno': request.GET.get('ticketno'),
        'laststatus': request.GET.get('status'),
        'requester': request.GET.get('requester'),
        # ...other context variables...
    }
    return render(request, 'template/ticketbyemail.html', context)

def ticket_rows_template(request):
    """Render the ticket rows template"""
    context = {
        'user_name': request.GET.get('user_name'),
        'user_id': request.GET.get('user_id'),
        'created': request.GET.get('created'),
        'comment': request.GET.get('comment'),
    }
    return render(request, 'template/updateticketrows.html', context)

def reset_password_template(request):
    """Render the reset password email template"""
    context = {
        'verifylink': request.GET.get('verifylink'),
    }
    return render(request, 'template/resetpassword.html', context)


#Tcicket super user views


class HomeView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        return context

class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add dashboard-specific context
        return context

class AnalyticsView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/analytics.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add analytics-specific context
        return context

class AnalyticsDetailView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/analytics_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'type': kwargs.get('type'),
            'id': kwargs.get('id'),
            'from_date': self.request.GET.get('from'),
            'to_date': self.request.GET.get('to')
        })
        return context

class DashboardSummaryView(LoginRequiredMixin, View):
    def get(self, request):
        """Get dashboard summary data"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT status_id, status_name, COUNT(*) as count 
                FROM tickets 
                GROUP BY status_id, status_name
            """)
            results = self.dictfetchall(cursor)
        return JsonResponse(results, safe=False)

    def dictfetchall(self, cursor):
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

class TicketDataView(LoginRequiredMixin, View):
    def post(self, request):
        """Get ticket data for admin dashboard"""
        with connection.cursor() as cursor:
            cursor.callproc('sp_get_admin_ticket_data', [request.user.id])
            results = cursor.fetchall()
        return JsonResponse(results, safe=False)
