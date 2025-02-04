from django.urls import path
from . import views
# from .views import ticket_superuser as admin_views

urlpatterns = [
    # Authentication URLs
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('change-password/', views.change_password, name='change_password'),
    path('verify-account/<str:activation_code>/', views.verify_account, name='verify_account'),
    path('new-account/', views.new_account, name='new_account'),

    # Ticket URLs
    path('tickets/', views.all_tickets, name='all_tickets'),  # Use a proper view name
    path('ticket/new/', views.new_ticket, name='new_ticket'),
    path('tickets/all/', views.all_tickets, name='all_tickets'),
    path('tickets/search/', views.advanced_search, name='advanced_search'),
    path('ticket/<int:ticket_id>/', views.view_ticket, name='view_ticket'),
    path('ticket/<int:ticket_id>/detail/', views.view_ticket_detail, name='view_ticket_detail'),
    path('ticket/save/', views.save_ticket, name='save_ticket'),
    path('ticket/update/', views.update_ticket, name='update_ticket'),
    path('user/settings/', views.user_settings, name='user_settings'),

    # MLoyalty URLs
    path('mloyal/', views.index, name='mloyal_index'),
    path('mloyal/dashboard/', views.mloyal_dashboard, name='mloyal_dashboard'),
    path('mloyal/ticket/<int:ticket_id>/', views.mloyal_view_ticket, name='mloyal_view_ticket'),

    # Super User URLs
    path('admin/', views.TicketSuperUserView.as_view(), name='superuser_home'),
    path('admin/new-ticket/', views.AdminNewTicketView.as_view(), name='admin_new_ticket'),
    path('admin/dashboard/<int:id>/<str:filtertype>/<str:days>/<str:vtype>/<str:ticketno>/', 
         views.TicketDashboardView.as_view(), name='admin_dashboard'),
    path('admin/ticket/<int:ticketid>/', views.ViewTicketView.as_view(), name='admin_view_ticket'),
    path('admin/ticket-data/', views.TicketDataView.as_view(), name='admin_ticket_data'),
    path('admin/save-ticket/', views.SaveTicketView.as_view(), name='admin_save_ticket'),
    path('admin/all-tickets/<int:user_id>/', views.AllTicketsView.as_view(), name='admin_all_tickets'),

    # Template URLs
    path('template/ticket/update/', views.update_ticket_template, name='update_ticket_template'),
    path('template/ticket/email/', views.ticket_email_template, name='ticket_email_template'),
    path('template/ticket/rows/', views.ticket_rows_template, name='ticket_rows_template'),
    path('template/reset-password/', views.reset_password_template, name='reset_password_template'),
    
    # # Ticket Super User URLs 
    # path('admin/home/', admin_views.HomeView.as_view(), name='admin_home'),
    # path('admin/dashboard/', admin_views.DashboardView.as_view(), name='admin_dashboard'),
    # path('admin/analytics/', admin_views.AnalyticsView.as_view(), name='admin_analytics'),
    # path('admin/analytics/detail/<int:id>/', admin_views.AnalyticsDetailView.as_view(), name='admin_analytics_detail'),
    # path('admin/tickets/data/', admin_views.TicketDataView.as_view(), name='admin_ticket_data'),
    # path('admin/tickets/summary/', admin_views.DashboardSummaryView.as_view(), name='admin_dashboard_summary'),
]
