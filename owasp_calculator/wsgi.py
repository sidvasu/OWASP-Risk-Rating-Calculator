"""
WSGI config for the OWASP Risk Rating Calculator project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "owasp_calculator.settings")

application = get_wsgi_application()
