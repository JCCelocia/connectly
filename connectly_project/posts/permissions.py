from rest_framework.permissions import BasePermission

class IsPostAuthor(BasePermission):
    """
    Custom permission to allow only the author of a post to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        return obj.author == request.user


class CanCreatePost(BasePermission):
    """
    Permission for users who can create posts (Admin, Editor).
    """
    def has_permission(self, request, view):
        return request.user.has_perm('app.can_create_post')


class CanEditPost(BasePermission):
    """
    Permission for users who can edit posts (Admin, Editor).
    """
    def has_permission(self, request, view):
        return request.user.has_perm('app.can_edit_post')


class CanDeletePost(BasePermission):
    """
    Permission for users who can delete posts (Admin).
    """
    def has_permission(self, request, view):
        return request.user.has_perm('app.can_delete_post')


class CanCreateComment(BasePermission):
    """
    Permission for users who can create comments (Admin, Editor, Viewer).
    """
    def has_permission(self, request, view):
        return request.user.has_perm('app.can_create_comment')


class CanDeleteComment(BasePermission):
    """
    Permission for users who can delete comments (Admin, Editor).
    """
    def has_permission(self, request, view):
        return request.user.has_perm('app.can_delete_comment')
