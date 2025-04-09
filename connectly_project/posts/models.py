from django.db import models
from django.contrib.auth.models import User, Group, Permission

class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username


class Post(models.Model):
    content = models.TextField()
    author = models.ForeignKey(User, related_name='posts', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        permissions = [
            ('can_create_post', 'Can create post'),
            ('can_edit_post', 'Can edit post'),
            ('can_delete_post', 'Can delete post'),
        ]

    def __str__(self):
        return f"Post by {self.author}"


class Comment(models.Model):
    text = models.TextField()
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        permissions = [
            ('can_create_comment', 'Can create comment'),
            ('can_delete_comment', 'Can delete comment'),
        ]

    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"


# Utility function to create roles and assign permissions
def create_roles_and_permissions():
    # Create groups (roles)
    admin_group, _ = Group.objects.get_or_create(name='Admin')
    editor_group, _ = Group.objects.get_or_create(name='Editor')
    viewer_group, _ = Group.objects.get_or_create(name='Viewer')

    # Assign permissions to Admin group
    admin_group.permissions.set(
        Permission.objects.filter(codename__in=['can_create_post', 'can_edit_post', 'can_delete_post', 'can_create_comment', 'can_delete_comment'])
    )

    # Assign permissions to Editor group
    editor_group.permissions.set(
        Permission.objects.filter(codename__in=['can_create_post', 'can_edit_post', 'can_create_comment'])
    )

    # Assign permissions to Viewer group
    viewer_group.permissions.set(
        Permission.objects.filter(codename__in=['can_create_comment'])
    )
    
    
    # This class is a metaclass (a class of a class) that ensures only one instance of any class using it as a metaclass can exist.
class Singleton(type):
    # dictionary: Stores instances of the classes.
    _instances = {}
    # method: When an instance is created, it checks if the class has already an instance. If not, it creates and stores a new instance. If yes, it returns the existing instance.    
    def __call__(cls, *args, **kwargs):
        # sourcery skip: instance-method-first-arg-name
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

# uses Singleton as its metaclass, meaning it will only ever have one instance.
class PasswordSingleton(metaclass=Singleton):
    # Initializes the instance with a password attribute.
    def __init__(self, password):
        self.password = password

# __init__ method that takes a password argument and stores it as an instance attribute.
class PasswordClass:
    def __init__(self, password):
            self.password = password

# This is the Factory class that is responsible for creating instances of classes.
# _creators dictionary: Stores the creators (constructors) of the registered classes.
# register_class method: Registers a class with the factory by associating it with a key.
# create_instance method: Creates an instance of the registered class using the provided key and arguments.
class PasswordFactory:
    def __init__(self):
        self._creators = {}

    def register_class(self, key, creator):
        self._creators[key] = creator

    def create_instance(self, key, *args, **kwargs):
        # sourcery skip: reintroduce-else, swap-if-else-branches, use-named-expression
        creator = self._creators.get(key)
        if not creator:
            raise ValueError(f"Class not registered for key: {key}")
        return creator(*args, **kwargs)

