#!/usr/bin/env python
#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from django.core.management import execute_from_command_line

def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'connectly_project.settings')

    # Import your models after Django has initialized settings
    import django
    django.setup()  # Initialize Django settings and app registry
    
    from django.contrib.auth.models import Group, User

    # Database operations (now inside the main function)
    try:
        admin_group, created = Group.objects.get_or_create(name="Admin")
        user = User.objects.get(username="admin_user")
        user.groups.add(admin_group)
        print(f"User {user.username} added to 'Admin' group")
    except User.DoesNotExist:
        print("User 'admin_user' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

    try:
        execute_from_command_line(sys.argv)
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc


if __name__ == '__main__':
    main()
