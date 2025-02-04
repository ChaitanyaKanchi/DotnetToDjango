from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def login_required_with_message(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.user.is_authenticated:
            return function(request, *args, **kwargs)
        messages.error(request, 'Please login to continue.')
        return redirect('login')
    return wrap

def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Check if user is authenticated
            if not request.user.is_authenticated:
                messages.error(request, 'Please login to continue.')
                return redirect('login')
            
            # Allow superusers to access everything
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # For regular users, check if they have UserProfile with role
            try:
                user_profile = request.user.userdetail
                if user_profile.role_id in allowed_roles:
                    return view_func(request, *args, **kwargs)
            except:
                pass
            
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard')
            
        return wrapper
    return decorator

def superuser_required(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_superuser:
            return function(request, *args, **kwargs)
        messages.error(request, 'Superuser access required.')
        return redirect('dashboard')
    return wrap
