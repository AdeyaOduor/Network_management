''' 
Key Features:
    Responsive Design: Works perfectly on mobile, tablet, and desktop
    Modern UI: Clean, professional design with Tailwind CSS
    Interactive Elements: Hover effects, animations, and smooth transitions
    Mobile-Friendly: Collapsible sidebar with overlay
    Notification System: Beautiful message alerts with auto-dismiss
    Status Indicators: Online/offline status with visual cues
    Accessibility: Proper contrast and keyboard navigation support
    Professional Layout: Organized navigation and content structure

in terminal:
# Setup MySQL if not yet installed:
sudo mysql_secure_installation
sudo mysql -u root -p < setup_mysql.sql

# Update system if not yet updataed
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3-pip python3-venv nginx mysql-server redis-server git

pip install django mysqlclient netmiko cryptography django-ratelimit
django-admin startproject DjangoRouterManager
cd DjangoRouterManager
touch .env
touch requirements.txt
python3 -m venv routerenv, 
source routerenv/scripts/activate, 
python3 manage.py startapp router

'''
# Django Settings in .env file
DEBUG=False
SECRET_KEY=your-production-secret-key-change-this
ALLOWED_HOSTS=.yourdomain.com,localhost,127.0.0.1

# Database in .env file
DB_NAME=router_acl_manager
DB_USER=router_user
DB_PASSWORD=strong-password-here
DB_HOST=localhost
DB_PORT=3306

ENCRYPTION_KEY=your-32-url-safe-base64-encryption-key
REDIS_URL=redis://localhost:6379/0
CSRF_TRUSTED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# requirements.txt
Django==4.2.7
mysqlclient==2.1.1
netmiko==4.1.2
cryptography==41.0.7
django-ratelimit==3.0.1
gunicorn==21.2.0
whitenoise==6.6.0
python-dotenv==1.0.0
django-environ==0.10.0
celery==5.3.4
redis==5.0.1
django-redis==5.3.0
psutil==5.9.6
paramiko==3.3.1


# Settings.py
import os
import base64
import environ
from pathlib import Path
from cryptography.fernet import Fernet


INSTALLED_APPS = [
    # ...
   'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'router_acl_manager',
    'django_celery_results',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'router_manager.middleware.RateLimitMiddleware',
]

ROOT_URLCONF = 'router_acls.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'router_acls.wsgi.application'

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Initialize environment variables
env = environ.Env()
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# Security settings
SECRET_KEY = env('SECRET_KEY')
DEBUG = env.bool('DEBUG', default=False)
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['localhost', '127.0.0.1'])

# Generate encryption key (run once and store securely)
# ENCRYPTION_KEY = Fernet.generate_key()
# ENCRYPTION_KEY = b'your-generated-encryption-key-here'  # Store in environment variable

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'router_acl_manager',
        'USER': 'your_mysql_user',
        'PASSWORD': 'your_mysql_password',
        'HOST': 'localhost',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            'charset': 'utf8mb4',
        },
    }
}

# production Database
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': env('router_acl_manager'),
#         'USER': env('Dev_Admin'),
#         'PASSWORD': env('DB_PASSWORD'),
#         'HOST': env('DB_HOST', default='localhost'),
#         'PORT': env('DB_PORT', default='3306'),
#         'OPTIONS': {
#             'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
#             'charset': 'utf8mb4',
#         },
#     }
# }

# Rate limiting
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True # For HTTPS
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Encryption in production
ENCRYPTION_KEY = env('ENCRYPTION_KEY').encode()

# Redis Cache
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Celery Configuration
CELERY_BROKER_URL = env('REDIS_URL')
CELERY_RESULT_BACKEND = 'django-db'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'maxBytes': 1024 * 1024 * 5,  # 5 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'netmiko_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'netmiko.log',
            'maxBytes': 1024 * 1024 * 5,
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'router_manager': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
        'netmiko': {
            'handlers': ['netmiko_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# models.py
from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from cryptography.fernet import Fernet
from django.conf import settings
import base64
import re

class EncryptedField:
    def __init__(self):
        self.cipher = Fernet(settings.ENCRYPTION_KEY)
    
    def encrypt(self, data):
        if data is None:
            return None
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data):
        if encrypted_data is None:
            return None
        return self.cipher.decrypt(encrypted_data.encode()).decode()

class Router(models.Model):
    AUTH_METHODS = [
        ('password', 'Password'),
        ('ssh_key', 'SSH Key'),
    ]
    
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=100)
    auth_method = models.CharField(max_length=10, choices=AUTH_METHODS, default='password')
    _password = models.TextField(db_column='password', blank=True, null=True)  # Encrypted
    ssh_key = models.TextField(blank=True, null=True)  # Encrypted SSH private key
    ssh_key_passphrase = models.TextField(blank=True, null=True)  # Encrypted
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_routers')
    
    # Permission fields
    allowed_users = models.ManyToManyField(User, blank=True, related_name='accessible_routers')
    is_active = models.BooleanField(default=True)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encryptor = EncryptedField()
    
    @property
    def password(self):
        if self._password:
            return self.encryptor.decrypt(self._password)
        return None
    
    @password.setter
    def password(self, value):
        if value:
            self._password = self.encryptor.encrypt(value)
    
    @property
    def decrypted_ssh_key(self):
        if self.ssh_key:
            return self.encryptor.decrypt(self.ssh_key)
        return None
    
    @decrypted_ssh_key.setter
    def decrypted_ssh_key(self, value):
        if value:
            self.ssh_key = self.encryptor.encrypt(value)
    
    @property
    def decrypted_ssh_passphrase(self):
        if self.ssh_key_passphrase:
            return self.encryptor.decrypt(self.ssh_key_passphrase)
        return None
    
    @decrypted_ssh_passphrase.setter
    def decrypted_ssh_passphrase(self, value):
        if value:
            self.ssh_key_passphrase = self.encryptor.encrypt(value)
    
    def clean(self):
        if self.auth_method == 'password' and not self._password:
            raise ValidationError('Password is required for password authentication')
        if self.auth_method == 'ssh_key' and not self.ssh_key:
            raise ValidationError('SSH key is required for SSH key authentication')
    
    def has_access(self, user):
        return user.is_superuser or user == self.created_by or user in self.allowed_users.all()
    
    def __str__(self):
        return f"{self.name} ({self.ip_address})"
    
    class Meta:
        permissions = [
            ('manage_all_routers', 'Can manage all routers'),
            ('view_router', 'Can view router'),
            ('configure_router', 'Can configure router'),
        ]

class ACLRule(models.Model):
    router = models.ForeignKey(Router, on_delete=models.CASCADE)
    acl_name = models.CharField(max_length=100)
    rule = models.TextField()
    description = models.TextField(blank=True)
    sequence_number = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    
    def clean(self):
        # Validate ACL rule format
        if not re.match(r'^(permit|deny|remark)\s+', self.rule.lower()):
            raise ValidationError('ACL rule must start with permit, deny, or remark')
        
        # Prevent SQL injection and other attacks in rule content
        if any(char in self.rule for char in [';', '--', '/*', '*/', 'xp_']):
            raise ValidationError('Invalid characters in ACL rule')
    
    def __str__(self):
        return f"{self.acl_name} - {self.rule[:50]}..."
    
    class Meta:
        ordering = ['sequence_number']
        unique_together = ['router', 'acl_name', 'sequence_number']


# services/netmiko_service.py
import logging
from netmiko import ConnectHandler
from django.core.exceptions import PermissionDenied
from django.conf import settings

logger = logging.getLogger(__name__)

class NetmikoService:
    @staticmethod
    def connect_to_router(router, user):
        """Connect to the router using SSH with proper authentication."""
        if not router.has_access(user):
            raise PermissionDenied("You don't have access to this router")
        
        if not router.is_active:
            raise Exception("Router is not active")
        
        device = {
            'device_type': 'cisco_ios',
            'host': router.ip_address,
            'username': router.username,
            'timeout': 30,
            'session_timeout': 30,
            'banner_timeout': 15,
        }
        
        if router.auth_method == 'password':
            device['password'] = router.password
        elif router.auth_method == 'ssh_key':
            device['use_keys'] = True
            device['key_file'] = '/tmp/temp_ssh_key'  # We'll handle this securely
            # In production, use a secure temporary file handling
            raise NotImplementedError("SSH key authentication not fully implemented")
        
        try:
            connection = ConnectHandler(**device)
            logger.info(f"Successfully connected to {router.ip_address}")
            return connection
        except Exception as e:
            logger.error(f"Failed to connect to {router.ip_address}: {str(e)}")
            raise Exception(f"Connection failed: {str(e)}")

    @staticmethod
    def validate_acl_rule(rule):
        """Validate ACL rule format and security."""
        import re
        
        # Basic validation
        if not re.match(r'^(permit|deny|remark)\s+', rule.lower()):
            raise ValidationError('ACL rule must start with permit, deny, or remark')
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r';', r'--', r'/\*', r'\*/', r'xp_', r'exec\s+', r'\!'
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, rule, re.IGNORECASE):
                raise ValidationError('ACL rule contains potentially dangerous patterns')
        
        return True

    @staticmethod
    def add_acl_rule(connection, acl_name, rule):
        """Add a rule to the specified ACL with validation."""
        NetmikoService.validate_acl_rule(rule)
        
        commands = [
            f"ip access-list extended {acl_name}",
            rule
        ]
        try:
            output = connection.send_config_set(commands)
            # Save configuration
            connection.save_config()
            logger.info(f"Added rule to {acl_name}: {rule}")
            return output
        except Exception as e:
            logger.error(f"Failed to add rule: {str(e)}")
            raise Exception(f"Failed to add ACL rule: {str(e)}")

    @staticmethod
    def show_acl(connection, acl_name):
        """Show the current ACL configuration."""
        try:
            # Validate ACL name to prevent injection
            if not re.match(r'^[a-zA-Z0-9_-]+$', acl_name):
                raise ValidationError('Invalid ACL name')
                
            output = connection.send_command(f"show access-lists {acl_name}")
            logger.info(f"Retrieved ACL {acl_name} configuration")
            return output
        except Exception as e:
            logger.error(f"Failed to show ACL: {str(e)}")
            raise Exception(f"Failed to retrieve ACL: {str(e)}")

    @staticmethod
    def disconnect_router(connection):
        """Disconnect from the router."""
        if connection:
            try:
                connection.disconnect()
                logger.info("Disconnected from router")
            except Exception as e:
                logger.warning(f"Error during disconnect: {str(e)}")

# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from ratelimit.decorators import ratelimit
from ratelimit.core import get_usage
from .models import Router, ACLRule
from .services.netmiko_service import NetmikoService
import re

@login_required
@permission_required('router_manager.view_router', raise_exception=True)
@ratelimit(key='user', rate='10/m', method='GET', block=True)
def router_list(request):
    if request.user.has_perm('router_manager.manage_all_routers'):
        routers = Router.objects.filter(is_active=True)
    else:
        routers = Router.objects.filter(
            is_active=True,
            allowed_users=request.user
        ) | Router.objects.filter(
            is_active=True,
            created_by=request.user
        )
    
    return render(request, 'router_manager/router_list.html', {
        'routers': routers.distinct()
    })

@login_required
@permission_required('router_manager.view_router', raise_exception=True)
@ratelimit(key='user', rate='5/m', method='GET', block=True)
def router_detail(request, router_id):
    router = get_object_or_404(Router, id=router_id, is_active=True)
    
    if not router.has_access(request.user):
        raise PermissionDenied("You don't have access to this router")
    
    acl_rules = ACLRule.objects.filter(router=router, is_active=True)
    
    # Get rate limit info
    usage = get_usage(request, key='user', rate='5/m', method='POST')
    
    return render(request, 'router_manager/router_detail.html', {
        'router': router,
        'acl_rules': acl_rules,
        'rate_limit': usage
    })

@login_required
@permission_required('router_manager.configure_router', raise_exception=True)
@ratelimit(key='user', rate='3/m', method='POST', block=True)
def add_acl_rule(request, router_id):
    router = get_object_or_404(Router, id=router_id, is_active=True)
    
    if not router.has_access(request.user):
        raise PermissionDenied("You don't have access to this router")
    
    if request.method == 'POST':
        acl_name = request.POST.get('acl_name', '').strip()
        rule = request.POST.get('rule', '').strip()
        description = request.POST.get('description', '').strip()
        
        # Input validation
        if not re.match(r'^[a-zA-Z0-9_-]+$', acl_name):
            messages.error(request, "Invalid ACL name. Use only letters, numbers, underscores, and hyphens.")
            return redirect('router_detail', router_id=router_id)
        
        try:
            # Validate ACL rule
            NetmikoService.validate_acl_rule(rule)
            
            # Connect to router
            connection = NetmikoService.connect_to_router(router, request.user)
            
            # Add ACL rule
            output = NetmikoService.add_acl_rule(connection, acl_name, rule)
            
            # Show updated ACL
            acl_output = NetmikoService.show_acl(connection, acl_name)
            
            # Disconnect
            NetmikoService.disconnect_router(connection)
            
            # Save to database
            ACLRule.objects.create(
                router=router,
                acl_name=acl_name,
                rule=rule,
                description=description,
                created_by=request.user
            )
            
            messages.success(request, "ACL rule added successfully!")
            
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
    
    return redirect('router_detail', router_id=router_id)

@login_required
@permission_required('router_manager.view_router', raise_exception=True)
@ratelimit(key='user', rate='5/m', method='GET', block=True)
def show_acl(request, router_id):
    router = get_object_or_404(Router, id=router_id, is_active=True)
    
    if not router.has_access(request.user):
        raise PermissionDenied("You don't have access to this router")
    
    acl_name = request.GET.get('acl_name', '').strip()
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', acl_name):
        messages.error(request, "Invalid ACL name")
        return redirect('router_detail', router_id=router_id)
    
    try:
        connection = NetmikoService.connect_to_router(router, request.user)
        acl_output = NetmikoService.show_acl(connection, acl_name)
        NetmikoService.disconnect_router(connection)
        
        return render(request, 'router_manager/show_acl.html', {
            'router': router,
            'acl_name': acl_name,
            'acl_output': acl_output
        })
        
    except Exception as e:
        messages.error(request, f"Error: {str(e)}")
        return redirect('router_detail', router_id=router_id)

# urls.py
from django.urls import path
from . import views

app_name = 'router_manager'

urlpatterns = [
    path('', views.router_list, name='router_list'),
    path('router/<int:router_id>/', views.router_detail, name='router_detail'),
    path('router/<int:router_id>/show_acl/', views.show_acl, name='show_acl'),
]


# templates/base.html
{% load static %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Management System - {% block title %}Home{% endblock %}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: {
                            50: '#eff6ff',
                            100: '#dbeafe',
                            500: '#3b82f6',
                            600: '#2563eb',
                            700: '#1d4ed8',
                            800: '#1e40af',
                            900: '#1e3a8a',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        .sidebar {
            transition: all 0.3s ease;
        }
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            .sidebar.mobile-open {
                transform: translateX(0);
            }
        }
        .notification {
            animation: slideIn 0.3s ease, fadeOut 0.3s ease 4.7s forwards;
        }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes fadeOut {
            from { opacity: 1; }
            to { opacity: 0; }
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen flex">
    <!-- Mobile menu button -->
    <button class="md:hidden fixed top-4 left-4 z-50 p-2 bg-primary-600 text-white rounded-lg shadow-lg" 
            onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </button>

    <!-- Sidebar -->
    <div class="sidebar bg-white w-64 min-h-screen shadow-lg fixed md:relative z-40">
        <div class="p-6 border-b border-gray-200">
            <div class="flex items-center space-x-3">
                <div class="bg-primary-600 p-3 rounded-lg">
                    <i class="fas fa-route text-white text-xl"></i>
                </div>
                <div>
                    <h1 class="text-xl font-bold text-gray-800">Router Manager</h1>
                    <p class="text-sm text-gray-600">Network Control Center</p>
                </div>
            </div>
        </div>

        <nav class="p-4">
            <div class="mb-6">
                <h2 class="text-xs uppercase tracking-wider text-gray-500 font-semibold mb-3 px-2">Main Navigation</h2>
                <a href="{% url 'router_manager:router_list' %}" 
                   class="flex items-center space-x-3 p-3 rounded-lg text-gray-700 hover:bg-primary-50 hover:text-primary-600 transition-colors mb-2 {% if request.resolver_match.url_name == 'router_list' %}bg-primary-50 text-primary-600 border-r-2 border-primary-600{% endif %}">
                    <i class="fas fa-server w-5"></i>
                    <span>Routers</span>
                </a>
                <a href="#" class="flex items-center space-x-3 p-3 rounded-lg text-gray-700 hover:bg-primary-50 hover:text-primary-600 transition-colors mb-2">
                    <i class="fas fa-shield-alt w-5"></i>
                    <span>ACL Management</span>
                </a>
                <a href="#" class="flex items-center space-x-3 p-3 rounded-lg text-gray-700 hover:bg-primary-50 hover:text-primary-600 transition-colors mb-2">
                    <i class="fas fa-history w-5"></i>
                    <span>Audit Log</span>
                </a>
            </div>

            <div class="mb-6">
                <h2 class="text-xs uppercase tracking-wider text-gray-500 font-semibold mb-3 px-2">Administration</h2>
                <a href="#" class="flex items-center space-x-3 p-3 rounded-lg text-gray-700 hover:bg-primary-50 hover:text-primary-600 transition-colors mb-2">
                    <i class="fas fa-users-cog w-5"></i>
                    <span>User Management</span>
                </a>
                <a href="#" class="flex items-center space-x-3 p-3 rounded-lg text-gray-700 hover:bg-primary-50 hover:text-primary-600 transition-colors mb-2">
                    <i class="fas fa-cog w-5"></i>
                    <span>Settings</span>
                </a>
            </div>
        </nav>

        <div class="absolute bottom-0 w-full p-4 border-t border-gray-200">
            <div class="flex items-center space-x-3 p-3">
                <div class="w-10 h-10 bg-primary-100 rounded-full flex items-center justify-center">
                    <i class="fas fa-user text-primary-600"></i>
                </div>
                <div class="flex-1 min-w-0">
                    <p class="text-sm font-medium text-gray-800 truncate">{{ user.username }}</p>
                    <p class="text-xs text-gray-600 truncate">{{ user.email|default:"No email" }}</p>
                </div>
                <a href="{% url 'admin:logout' %}" class="p-2 text-gray-400 hover:text-red-500 transition-colors" title="Logout">
                    <i class="fas fa-sign-out-alt"></i>
                </a>
            </div>
        </div>
    </div>

    <!-- Main content -->
    <div class="flex-1 flex flex-col md:ml-0">
        <!-- Header -->
        <header class="bg-white shadow-sm border-b border-gray-200">
            <div class="px-6 py-4">
                <div class="flex items-center justify-between">
                    <div>
                        <h1 class="text-2xl font-bold text-gray-800">{% block page_title %}Router Management{% endblock %}</h1>
                        <p class="text-sm text-gray-600">{% block page_subtitle %}Manage network devices and ACL rules{% endblock %}</p>
                    </div>
                    
                    <div class="flex items-center space-x-4">
                        <div class="hidden md:flex items-center space-x-2 text-sm text-gray-600">
                            <i class="fas fa-bolt text-green-500"></i>
                            <span>System Online</span>
                        </div>
                        <div class="relative">
                            <button class="p-2 text-gray-400 hover:text-gray-600 transition-colors">
                                <i class="fas fa-bell"></i>
                                <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <!-- Messages/Notifications -->
        {% if messages %}
        <div class="px-6 py-2 space-y-2">
            {% for message in messages %}
            <div class="notification bg-{% if message.tags == 'success' %}green{% elif message.tags == 'error' %}red{% else %}blue{% endif %}-100 border border-{% if message.tags == 'success' %}green{% elif message.tags == 'error' %}red{% else %}blue{% endif %}-400 text-{% if message.tags == 'success' %}green{% elif message.tags == 'error' %}red{% else %}blue{% endif %}-700 px-4 py-3 rounded-lg relative">
                <div class="flex items-center">
                    <i class="fas fa-{% if message.tags == 'success' %}check-circle{% elif message.tags == 'error' %}exclamation-circle{% else %}info-circle{% endif %} mr-2"></i>
                    <span class="block sm:inline">{{ message }}</span>
                    <button class="absolute top-0 right-0 p-2" onclick="this.parentElement.parentElement.remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- Content -->
        <main class="flex-1 p-6">
            {% block content %}
            <!-- Page content will be inserted here -->
            {% endblock %}
        </main>

        <!-- Footer -->
        <footer class="bg-white border-t border-gray-200 mt-auto">
            <div class="px-6 py-4">
                <div class="flex flex-col md:flex-row justify-between items-center">
                    <p class="text-sm text-gray-600">
                        &copy; 2024 Router Management System. All rights reserved.
                    </p>
                    <div class="flex items-center space-x-4 mt-2 md:mt-0">
                        <span class="text-sm text-gray-500">v1.0.0</span>
                        <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        <span class="text-sm text-green-600">Operational</span>
                    </div>
                </div>
            </div>
        </footer>
    </div>

    <!-- Mobile overlay -->
    <div class="fixed inset-0 bg-black bg-opacity-50 z-30 md:hidden hidden" id="mobileOverlay" onclick="toggleSidebar()"></div>

    <script>
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            const overlay = document.getElementById('mobileOverlay');
            sidebar.classList.toggle('mobile-open');
            overlay.classList.toggle('hidden');
        }

        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function(event) {
            const sidebar = document.querySelector('.sidebar');
            const overlay = document.getElementById('mobileOverlay');
            const isMobile = window.innerWidth < 768;
            
            if (isMobile && !sidebar.contains(event.target) && !event.target.closest('[onclick="toggleSidebar()"]')) {
                sidebar.classList.remove('mobile-open');
                overlay.classList.add('hidden');
            }
        });

        // Auto-remove notifications after 5 seconds
        setTimeout(() => {
            document.querySelectorAll('.notification').forEach(notification => {
                notification.remove();
            });
        }, 5000);

        // Responsive adjustments
        function handleResize() {
            const sidebar = document.querySelector('.sidebar');
            const overlay = document.getElementById('mobileOverlay');
            
            if (window.innerWidth >= 768) {
                sidebar.classList.remove('mobile-open');
                overlay.classList.add('hidden');
            }
        }

        window.addEventListener('resize', handleResize);
        handleResize(); // Initial call
    </script>
</body>
</html>


# templates/router_list.html
{% extends 'router_manager/base.html' %}

{% block title %}Router List{% endblock %}
{% block page_title %}Network Routers{% endblock %}
{% block page_subtitle %}Manage and configure your network devices{% endblock %}

{% block content %}
<div class="max-w-7xl mx-auto">
    <!-- Header with actions -->
    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 space-y-4 sm:space-y-0">
        <div>
            <h2 class="text-lg font-semibold text-gray-800">All Routers</h2>
            <p class="text-sm text-gray-600">{{ routers.count }} device(s) configured</p>
        </div>
        <div class="flex space-x-3">
            <button class="bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center space-x-2">
                <i class="fas fa-plus"></i>
                <span>Add Router</span>
            </button>
            <button class="border border-gray-300 hover:bg-gray-50 text-gray-700 px-4 py-2 rounded-lg transition-colors flex items-center space-x-2">
                <i class="fas fa-sync-alt"></i>
                <span>Refresh</span>
            </button>
        </div>
    </div>

    <!-- Router Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {% for router in routers %}
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 hover:shadow-md transition-shadow">
            <div class="p-6">
                <div class="flex items-start justify-between mb-4">
                    <div class="flex items-center space-x-3">
                        <div class="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center">
                            <i class="fas fa-router text-primary-600 text-xl"></i>
                        </div>
                        <div>
                            <h3 class="font-semibold text-gray-800">{{ router.name }}</h3>
                            <p class="text-sm text-gray-600">{{ router.ip_address }}</p>
                        </div>
                    </div>
                    <div class="w-3 h-3 bg-green-500 rounded-full animate-pulse" title="Online"></div>
                </div>

                <div class="space-y-2 mb-4">
                    <div class="flex items-center text-sm text-gray-600">
                        <i class="fas fa-user w-4 mr-2"></i>
                        <span>{{ router.username }}</span>
                    </div>
                    <div class="flex items-center text-sm text-gray-600">
                        <i class="fas fa-shield-alt w-4 mr-2"></i>
                        <span class="capitalize">{{ router.auth_method }}</span>
                    </div>
                    {% if router.description %}
                    <div class="flex items-start text-sm text-gray-600">
                        <i class="fas fa-info-circle w-4 mr-2 mt-0.5"></i>
                        <span class="line-clamp-2">{{ router.description }}</span>
                    </div>
                    {% endif %}
                </div>

                <div class="flex space-x-2 pt-4 border-t border-gray-100">
                    <a href="{% url 'router_manager:router_detail' router.id %}" 
                       class="flex-1 bg-primary-600 hover:bg-primary-700 text-white text-center py-2 px-3 rounded-lg text-sm transition-colors">
                        <i class="fas fa-cog mr-1"></i>Configure
                    </a>
                    <button class="w-10 h-10 border border-gray-300 hover:bg-gray-50 text-gray-600 rounded-lg transition-colors flex items-center justify-center">
                        <i class="fas fa-ellipsis-v"></i>
                    </button>
                </div>
            </div>
        </div>
        {% empty %}
        <div class="col-span-full text-center py-12">
            <div class="w-24 h-24 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <i class="fas fa-router text-gray-400 text-3xl"></i>
            </div>
            <h3 class="text-lg font-semibold text-gray-600 mb-2">No routers configured</h3>
            <p class="text-gray-500 mb-4">Get started by adding your first network device</p>
            <button class="bg-primary-600 hover:bg-primary-700 text-white px-6 py-2 rounded-lg transition-colors">
                <i class="fas fa-plus mr-2"></i>Add Router
            </button>
        </div>
        {% endfor %}
    </div>

    <!-- Stats Card -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mt-8">
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-sm text-gray-600">Total Routers</p>
                    <p class="text-2xl font-bold text-gray-800">{{ routers.count }}</p>
                </div>
                <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                    <i class="fas fa-server text-blue-600"></i>
                </div>
            </div>
        </div>
        
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-sm text-gray-600">Active ACL Rules</p>
                    <p class="text-2xl font-bold text-gray-800">{% comment %} Add ACL count {% endcomment %}0</p>
                </div>
                <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                    <i class="fas fa-shield-alt text-green-600"></i>
                </div>
            </div>
        </div>
        
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-sm text-gray-600">Online Devices</p>
                    <p class="text-2xl font-bold text-gray-800">{{ routers.count }}</p>
                </div>
                <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                    <i class="fas fa-wifi text-green-600"></i>
                </div>
            </div>
        </div>
        
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-sm text-gray-600">System Status</p>
                    <p class="text-2xl font-bold text-green-600">Operational</p>
                </div>
                <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                    <i class="fas fa-check-circle text-green-600"></i>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

# management/commands/setup_permissions.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from router_manager.models import Router

class Command(BaseCommand):
    help = 'Setup initial permissions and groups'
    
    def handle(self, *args, **options):
        # Create groups
        admin_group, created = Group.objects.get_or_create(name='Router Administrators')
        user_group, created = Group.objects.get_or_create(name='Router Users')
        
        # Get permissions
        content_type = ContentType.objects.get_for_model(Router)
        permissions = Permission.objects.filter(content_type=content_type)
        
        # Assign permissions to groups
        admin_group.permissions.set(permissions)
        user_group.permissions.set(permissions.filter(codename='view_router'))
        
        self.stdout.write(self.style.SUCCESS('Permissions setup completed'))


''' 
python manage.py makemigrations
python manage.py migrate
python manage.py setup_permissions              
'''
# ======================================= Deployment steps ========================================================
# Deployment script for Django Router ACL Management System

#deploy.sh

              # CLI

set -e

echo "Starting deployment..."

# Variables
PROJECT_DIR="/opt/router-acl-manager"
VENV_DIR="$PROJECT_DIR/venv"
REPO_URL="https://github.com/your-username/router-acl-manager.git"

# Create project directory
sudo mkdir -p $PROJECT_DIR
sudo chown $USER:$USER $PROJECT_DIR

# Clone or update repository
if [ ! -d "$PROJECT_DIR/.git" ]; then
    git clone $REPO_URL $PROJECT_DIR
else
    cd $PROJECT_DIR
    git pull origin main
fi

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv $VENV_DIR
fi

# Activate virtual environment
source $VENV_DIR/bin/activate

# Install dependencies
pip install -r $PROJECT_DIR/requirements.txt

# Create environment file
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cp $PROJECT_DIR/.env.example $PROJECT_DIR/.env
    echo "Please configure .env file before continuing"
    exit 1
fi

# Run migrations
python $PROJECT_DIR/manage.py migrate

# Collect static files
python $PROJECT_DIR/manage.py collectstatic --noinput

# Create superuser if not exists
python $PROJECT_DIR/manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'changeme123')
"

# Setup permissions
python $PROJECT_DIR/manage.py setup_permissions

echo "Deployment completed successfully!"
# -------------------------------------------------------------------------------

# nginx.conf
upstream router_acls {
    server unix:/opt/router-acl-manager/run/gunicorn.sock fail_timeout=0;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    client_max_body_size 4G;
    
    # Static files
    location /static/ {
        alias /opt/router-acl-manager/staticfiles/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Media files
    location /media/ {
        alias /opt/router-acl-manager/media/;
        expires 1d;
        add_header Cache-Control "public";
    }

    # Django application
    location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        proxy_pass http://router_acls;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
}
# -------------------------------------------------------------------------------------------------------------
# gunicorn.conf.py
import multiprocessing
import os

# Server socket
bind = "unix:/opt/router-acl-manager/run/gunicorn.sock"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 2

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Process naming
proc_name = 'router_acls'

# Server mechanics
daemon = False
pidfile = '/opt/router-acl-manager/run/gunicorn.pid'
umask = 0
user = None
group = None
tmp_upload_dir = None

# Logging
accesslog = '/opt/router-acl-manager/logs/gunicorn_access.log'
errorlog = '/opt/router-acl-manager/logs/gunicorn_error.log'
loglevel = 'info'

# Process naming
def when_ready(server):
    open('/tmp/app-initialized', 'w').close()
# ------------------------------------------------------------------------------------------
# gunicorn.service
[Unit]
Description=Router ACL Manager Gunicorn Daemon
After=network.target mysql.service redis-server.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/router-acl-manager
Environment=PATH=/opt/router-acl-manager/venv/bin
ExecStart=/opt/router-acl-manager/venv/bin/gunicorn --config gunicorn.conf.py router_acls.wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
# ------------------------------------------------------------------------------------------
# celery.service
[Unit]
Description=Router ACL Manager Celery Worker
After=network.target mysql.service redis-server.service

[Service]
Type=forking
User=www-data
Group=www-data
WorkingDirectory=/opt/router-acl-manager
Environment=PATH=/opt/router-acl-manager/venv/bin
ExecStart=/opt/router-acl-manager/venv/bin/celery -A router_acls worker --loglevel=info --logfile=/opt/router-acl-manager/logs/celery.log
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
# -----------------------------------------------------------------------------------------------------
# setup_mysql.sql
-- Create database and user
CREATE DATABASE IF NOT EXISTS router_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'router_user'@'localhost' IDENTIFIED BY 'strong-password-here';
GRANT ALL PRIVILEGES ON router_manager.* TO 'router_user'@'localhost';
FLUSH PRIVILEGES;

-- Create additional user for remote connections (if needed)
CREATE USER IF NOT EXISTS 'router_user'@'%' IDENTIFIED BY 'strong-password-here';
GRANT ALL PRIVILEGES ON router_manager.* TO 'router_user'@'%';
FLUSH PRIVILEGES;
# ------------------------------------------------------------------------------------------------------------
# security_setup.sh
#!/bin/bash
# Security hardening for Django Router ACL Management System

# Generate secret key
SECRET_KEY=$(python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")
echo "SECRET_KEY=$SECRET_KEY" >> /opt/router-acl-manager/.env

# Generate encryption key
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" >> /opt/router-acl-manager/.env

# Set proper permissions
chown -R www-data:www-data /opt/router-acl-manager
chmod -R 750 /opt/router-acl-manager
chmod 640 /opt/router-acl-manager/.env

# Create necessary directories
mkdir -p /opt/router-acl-manager/{logs,run,media,staticfiles}
chown www-data:www-data /opt/router-acl-manager/{logs,run,media,staticfiles}

# Setup firewall
ufw allow ssh
ufw allow 80
ufw allow 443
ufw --force enable

# Install SSL certificate (Certbot)
apt update
apt install -y certbot python3-certbot-nginx
certbot --nginx -d yourdomain.com -d www.yourdomain.com

echo "Security setup completed!"
# ----------------------------------------------
# Application Deployment
# Make deploy script executable
chmod +x deploy.sh

# Run deployment
./deploy.sh

# Run security setup
chmod +x security_setup.sh
./security_setup.sh
# -------------------------------------------------
# Service Configuration
# Copy systemd service files
sudo cp gunicorn.service /etc/systemd/system/
sudo cp celery.service /etc/systemd/system/

# Copy nginx config
sudo cp nginx.conf /etc/nginx/sites-available/router-acls
sudo ln -s /etc/nginx/sites-available/router-acls /etc/nginx/sites-enabled/

# Start services
sudo systemctl daemon-reload
sudo systemctl enable gunicorn celery nginx
sudo systemctl start gunicorn celery nginx
# ----------------------------------------------------------

# Monitoring and Maintenance
# Check service status
sudo systemctl status gunicorn
sudo systemctl status celery
sudo systemctl status nginx

# View logs
sudo tail -f /opt/router-acl-manager/logs/gunicorn_error.log
sudo tail -f /opt/router-acl-manager/logs/django.log
# -------------------------------------------------------------------
# Backup.sh
#!/bin/bash

# Backup script for Router ACL Management System

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
mysqldump -u router_user -p router_manager > $BACKUP_DIR/router_manager_$DATE.sql

# Backup encryption keys and configuration
cp /opt/router-acl-manager/.env $BACKUP_DIR/env_$DATE.backup

# Backup media files
tar -czf $BACKUP_DIR/media_$DATE.tar.gz -C /opt/router-acl-manager media/

# Backup logs
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz -C /opt/router-acl-manager logs/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql" -mtime +30 -delete
find $BACKUP_DIR -name "*.backup" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR"
# =================================================================================================================


# Python script that uses the netmiko library to automate ACL management on Cisco routers.
# pip install netmiko

# router_acl_manager.py
from netmiko import ConnectHandler
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

def connect_to_router(ip, username, password):
    """Connect to the router using SSH."""
    device = {
        'device_type': 'cisco_ios',
        'host': ip,
        'username': username,
        'password': password,
    }
    try:
        connection = ConnectHandler(**device)
        logging.info(f"Connected to {ip}")
        return connection
    except Exception as e:
        logging.error(f"Failed to connect to {ip}: {e}")
        return None

def add_acl_rule(connection, acl_name, rule):
    """Add a rule to the specified ACL."""
    command = f"ip access-list extended {acl_name}\n{rule}"
    try:
        output = connection.send_config_set(command)
        logging.info(f"Added rule to {acl_name}: {rule}")
        return output
    except Exception as e:
        logging.error(f"Failed to add rule: {e}")
        return None

def show_acl(connection, acl_name):
    """Show the current ACL configuration."""
    try:
        output = connection.send_command(f"show access-lists {acl_name}")
        logging.info(f"Current ACL {acl_name}:\n{output}")
        return output
    except Exception as e:
        logging.error(f"Failed to show ACL: {e}")
        return None

def disconnect_router(connection):
    """Disconnect from the router."""
    if connection:
        connection.disconnect()
        logging.info("Disconnected from the router.")

# Example usage
if __name__ == "__main__":
    # Router credentials
    router_ip = "192.168.1.1"
    username = "admin"
    password = "your_password"

    # Connect to the router
    conn = connect_to_router(router_ip, username, password)

    if conn:
        # Define ACL name and rules
        acl_name = "MY_ACL"
        rules = [
            "permit ip host 192.168.1.10 any",  # Allow traffic from a specific host
            "deny ip host 192.168.1.20 any",     # Block traffic from another host
            "permit tcp 192.168.1.0 0.0.0.255 any eq 80",  # Allow HTTP traffic
            "permit tcp 192.168.2.0 0.0.0.255 any eq 443", # Allow HTTPS traffic
            "deny ip any any"                    # Deny all other traffic
        ]

        # Add each rule to the ACL
        for rule in rules:
            add_acl_rule(conn, acl_name, rule)

        # Show the current ACL
        show_acl(conn, acl_name)

        # Disconnect from the router
        disconnect_router(conn)
''' 
Real-World Usage
This script can be used in various scenarios, such as:

    Network Management: Automate the deployment of ACLs across multiple routers in an enterprise network.
    Security Protocols: Quickly update ACLs to respond to security threats or changes in network policy.
    Configuration Backups: Regularly retrieve and save ACL configurations for auditing purposes.

Deployment
1. Access to Router Credentials
    Gather the IP addresses, usernames, and passwords for the routers you wish to manage.

2. Test Connectivity
    Before deploying the script, make sure you can SSH into the router from your machine using a terminal or SSH client.
    bash

    ssh admin@192.168.1.1

3. Modify the Script for Your Environment
    Update the script with the correct router IP addresses, usernames, and passwords.
    Customize the ACL rules as necessary for your network.

4. Running the Script
    Save the modified script (e.g., router_acl_manager.py).

    Run the script from your terminal:
    bash
    python3 router_acl_manager.py

5. Verify Changes on the Router
    After running the script, you should verify that the ACLs were applied correctly. You can do this by logging into the router and using 
    the following command:
    bash
    show access-lists MY_ACL
'''

# Example usage for multiple routers
if __name__ == "__main__":
    routers = [
        {"ip": "192.168.1.1", "username": "admin", "password": "password1"},
        {"ip": "192.168.1.2", "username": "admin", "password": "password2"},
    ]

    acl_name = "MY_ACL"
    rules = [
        "permit ip host 192.168.1.10 any",
        "deny ip host 192.168.1.20 any",
        "permit tcp 192.168.1.0 0.0.0.255 any eq 80",
        "permit tcp 192.168.2.0 0.0.0.255 any eq 443",
        "deny ip any any"
    ]

    for router in routers:
        conn = connect_to_router(router["ip"], router["username"], router["password"])
        if conn:
            for rule in rules:
                add_acl_rule(conn, acl_name, rule)
            show_acl(conn, acl_name)
            disconnect_router(conn)
            
