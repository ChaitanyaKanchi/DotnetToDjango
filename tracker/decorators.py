from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps
from django.http import JsonResponse

def login_required_with_message(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if not request.user.is_authenticated:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': 'Please login to continue',
                    'redirect': '/login/'
                }, status=401)
            messages.error(request, 'Please login to continue')
            return redirect('login')
        return function(request, *args, **kwargs)
    return wrap

def role_required(allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrap(request, *args, **kwargs):
            if not request.user.is_authenticated:
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Please login to continue',
                        'redirect': '/login/'
                    }, status=401)
                messages.error(request, 'Please login to continue')
                return redirect('login')
                
            if request.user.role_id not in allowed_roles:
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'error',
                        'message': 'You do not have permission to access this page',
                        'redirect': '/dashboard/'
                    }, status=403)
                messages.error(request, 'You do not have permission to access this page')
                return redirect('dashboard')
                
            return function(request, *args, **kwargs)
        return wrap
    return decorator

def superuser_required(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if not request.user.is_authenticated:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': 'Please login to continue',
                    'redirect': '/login/'
                }, status=401)
            messages.error(request, 'Please login to continue')
            return redirect('login')
            
        if not request.user.role_id == 1:  # Assuming 1 is superuser role_id
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': 'Superuser access required',
                    'redirect': '/dashboard/'
                }, status=403)
            messages.error(request, 'Superuser access required')
            return redirect('dashboard')
            
        return function(request, *args, **kwargs)
    return wrap
