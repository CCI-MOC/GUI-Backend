"""
Settings specific to the local deploy.
"""
import os
import sys

# This is used by dependencies (ex: chromogenic)
# without exposing 'secret' settings in Debug mode.
from atmosphere.settings import secrets
SECRETS_MODULE = secrets

globals().update(vars(sys.modules['atmosphere.settings']))

# Debug Mode
DEBUG = True
SEND_EMAILS = False

template_backends = filter(lambda t:
    t['BACKEND'] == 'django.template.backends.django.DjangoTemplates',
    TEMPLATES)
for backend in template_backends:
    if 'debug' in backend['OPTIONS']:
        backend['OPTIONS']['debug'] = True


ENFORCING = False


#Cloud-Operator specific information
SITE_NAME = 'MOC'
SITE_TITLE = 'MOC'

DEFAULT_EMAIL_DOMAIN = ''

# Required to send RequestTracker emails

ATMO_SUPPORT = ADMINS



MAINTENANCE_EXEMPT_USERNAMES = []


ATMO_DAEMON = (("Atmosphere Daemon", "robbaron@bu.edu"),)

# Django uses this one..
MANAGERS = ADMINS
SUPPORT_EMAIL = ADMINS[0][1]  # First email in ADMINS
SUPPORT_EMAIL_SIGNATURE = 'Atmosphere Support Team'

# These support links will be made available through Troposphere.
SUPPORT_LINKS = {'getting_started': "https://link_to.wiki.org/Using+Instances", 'new_provider': "https://link_to.wiki.org/Changing+Providers", "faq": "https://link_to.wiki.org/Cloud_FAQ"}

REPLICATION_PROVIDER_LOCATION = ''
MONTHLY_RESET_PROVIDER_LOCATIONS = []
USER_EMAIL_LOOKUP_METHOD = 'django_get_email_info'
EMAIL_LOOKUP_METHOD = 'djangoLookupEmail'

# Marked for deletion when BYOC is available to set "per-provider-defaults"
# Values must be integers or None.
DEFAULT_ALLOCATION_THRESHOLD = int(10080)
DEFAULT_ALLOCATION_DELTA = int(525600)

# Value must be dict or None.
DEFAULT_QUOTA = None

# Marked for deletion -- Use provider.cloud_config instead
DEFAULT_KEYSTONE_ROLE = '_member_'
DEFAULT_IP_LOOKUP = ''
DEFAULT_PASSWORD_UPDATE = 'keystone_password_update'
INSTANCE_HOSTNAMING_DOMAIN = 'massopencloud.org'
INSTANCE_HOSTNAMING_FORMAT = 'vm%(three)s-%(four)s.%(domain)s'
AUTO_CREATE_NEW_ACCOUNTS = True

# Logging
LOGGING_LEVEL = logging.DEBUG
# Logging level for dependencies.
DEP_LOGGING_LEVEL = logging.WARNING


PROJECT_ROOT = os.path.abspath(
    os.path.join(
    os.path.dirname(__file__), '../..'))

SERVER_URL = 'https://128.31.22.8'


DATABASES = {
    'default': {
        'NAME': 'atmosphere',
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'USER': 'atmo_app',
        'CONN_MAX_AGE': 60,
        'PASSWORD': 'atmosphere',
        'HOST': 'localhost',
        'PORT': 5432,
        'TEST': {
            'SERIALIZE': False
        }
    },
}


# Prevents warnings
ALLOWED_HOSTS = [u'128.31.22.8', SERVER_URL.replace('https://', '')]
CSRF_TRUSTED_ORIGINS = ALLOWED_HOSTS


# Atmosphere Keypair/Deployment Configs
ATMOSPHERE_PRIVATE_KEYFILE = os.path.join(PROJECT_ROOT, 'extras/ssh/id_rsa')
ATMOSPHERE_KEYPAIR_FILE = os.path.join(PROJECT_ROOT, 'extras/ssh/id_rsa.pub')
ATMOSPHERE_KEYPAIR_NAME = 'MOC_Keypair_1'


# Atmosphere App Configs
INSTANCE_SERVICE_URL = SERVER_URL + REDIRECT_URL + '/api/v1/notification'
INSTANCE_SERVICE_URL.replace('https', 'http')
API_SERVER_URL = SERVER_URL + REDIRECT_URL + '/resources/v1'
AUTH_SERVER_URL = SERVER_URL + REDIRECT_URL + '/auth'
DEPLOY_SERVER_URL = SERVER_URL.replace('https', 'http')


# Django-Celery Development settings
# CELERY_EAGER_PROPAGATES_EXCEPTIONS = True  # Issue #75



# Configure authentication plugin
AUTHENTICATION = {
    #GLOBAL
    "APP_NAME": SITE_TITLE,
    "SITE_NAME": ORG_NAME,
    "SERVER_URL": SERVER_URL,
    "TOKEN_EXPIRY_TIME": timedelta(days=1),
    "SELF_SIGNED_CERT": True,
    "LOGOUT_REDIRECT_URL": '/logout',

    #KEYSTONE -- Required for OpenstackLoginBackend
    "KEYSTONE_SERVER": 'http://localhost:8082/api/test/keystone/',
    "KEYSTONE_DOMAIN_NAME": 'Default',

    #CAS
    "CAS_SERVER": '',
    "CAS_AUTH_PREFIX": '/cas',

    #CAS+OAuth
    "OAUTH_CLIENT_KEY": '',
    "OAUTH_CLIENT_SECRET": '',
    "OAUTH_CLIENT_CALLBACK":  SERVER_URL + '/oauth2.0/callbackAuthorize',
    "OAUTH_ISSUE_USER": '',

    #LDAP
    "LDAP_SERVER": '',
    "LDAP_SERVER_DN": '',
    


    #GLOBUS
    "GLOBUS_OAUTH_ID": '',
    "GLOBUS_OAUTH_SECRET": '',
    "GLOBUS_OAUTH_CREDENTIALS_SCOPE": 'auth:login',
    "GLOBUS_OAUTH_ATMOSPHERE_SCOPE": '',
    "GLOBUS_TOKEN_URL": 'https://auth.globus.org/v2/oauth2/token',
    "GLOBUS_TOKENINFO_URL": 'https://auth.globus.org/v2/oauth2/token/introspect',
    "GLOBUS_AUTH_URL": 'https://auth.globus.org/v2/oauth2/authorize',
}

TEST = {
    'Testing: 1',
    'username': 'friday-test',
    'password': 'friday-test',
    'non_username':'dummy_user'  
}

ALWAYS_AUTH_USER = "atmosphere_user"


AUTHENTICATION_BACKENDS = (
    
    # Use MockLoginBackend first!
    #'django_cyverse_auth.authBackends.MockLoginBackend',
    'django.contrib.auth.backends.ModelBackend',

    # Use existing AuthTokens as a login backend (Emulation via API)
    'django_cyverse_auth.authBackends.AuthTokenLoginBackend',
    'django_cyverse_auth.authBackends.OpenstackLoginBackend',
    
    
    
    )
# UPDATE REST_FRAMEWORK
REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] = (
    'django_cyverse_auth.token.TokenAuthentication',  # Generic Tokens
    'rest_framework.authentication.SessionAuthentication',  # Session
    
    
    
)

# CASLIB
SERVER_URL = SERVER_URL + REDIRECT_URL
SERVICE_URL = SERVER_URL + '/CAS_serviceValidater?sendback=' + REDIRECT_URL + '/application/'
PROXY_URL = SERVER_URL + '/CAS_proxyUrl'
PROXY_CALLBACK_URL = SERVER_URL + '/CAS_proxyCallback'


# Atmosphere Ansible Deploy
ANSIBLE_ROOT = '/opt/dev/atmosphere-ansible'
# The root directory for the ansible deploy project.
# If this is emptry str then ansible deploys will not
# run and will warn that ansible is no configured.
ANSIBLE_CONFIG_FILE = os.path.join(ANSIBLE_ROOT, 'ansible/ansible.cfg')
ANSIBLE_HOST_FILE = os.path.join(ANSIBLE_ROOT, 'ansible/hosts')
ANSIBLE_GROUP_VARS_DIR = os.path.join(ANSIBLE_ROOT, 'ansible/group_vars')
ANSIBLE_PLAYBOOKS_DIR = os.path.join(ANSIBLE_ROOT, 'ansible/playbooks')
ANSIBLE_ROLES_PATH = os.path.join(ANSIBLE_ROOT, 'ansible/roles')

os.environ["ANSIBLE_CONFIG"] = ANSIBLE_CONFIG_FILE 

# LOGSTASH
LOGSTASH_HOST = ''
LOGSTASH_PORT = -1
try:
    import logstash
    import threepio
    has_logstash = True
except ImportError:
    has_logstash = False


METRIC_SERVER = ''


os.environ["LIBCLOUD_DEBUG"] = os.path.join(PROJECT_ROOT, "logs/libcloud.log")
os.environ["LIBCLOUD_DEBUG_PRETTY_PRINT_RESPONSE"] = "True"



if has_logstash and LOGSTASH_HOST:
    fh = logstash.TCPLogstashHandler(LOGSTASH_HOST, LOGSTASH_PORT,
                                     message_type='atmo-deploy', version=1)
    threepio.deploy_logger.addHandler(fh)



# Include runsslserver
INSTALLED_APPS += (
    'sslserver',
)



# Uncomment and add values to TACC_API if you intend to use the jetstream plugin
# INSTALLED_APPS += (
#     'jetstream',
# )
TACC_API_USER = ''
TACC_API_PASS = ''
TACC_API_URL = ''

# Validation Plugins:
# These plugins will be checked, in order, until one passes
# If all validation plugins fail, user will be "kicked out" of the API.
# NOTE: No VALIDATION_PLUGINS were present during configure.
VALIDATION_PLUGINS = [
    #'jetstream.plugins.auth.validation.XsedeProjectRequired',
    #'atmosphere.plugins.auth.validation.LDAPGroupRequired',
    'atmosphere.plugins.auth.validation.AlwaysAllow',
]
