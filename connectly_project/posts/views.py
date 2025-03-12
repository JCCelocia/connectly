import bcrypt
import django_filters.rest_framework
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics, filters
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from .models import User, Post, Comment, PasswordSingleton, PasswordClass, PasswordFactory
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from django.contrib.auth.models import make_password, check_password 



class UserListCreate(APIView):

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        
        passwordSingleton1 = PasswordSingleton("mypassword123")
        passwordSingleton2 = PasswordSingleton("mypassword1234")
        print('First singleton password is: ', passwordSingleton1.password)
        print('Second singleton password is: ', passwordSingleton2.password)
        print('Are they the same? ', passwordSingleton1 is passwordSingleton1)         
        
        factory = PasswordFactory()
        factory.register_class('password', PasswordClass)

        firstPassword = factory.create_instance('password', 'mypassword123')
        secondPassword = factory.create_instance('password', 'mypassword123456')
        print('First password from factory is: ', firstPassword.password)
        print('Second password from factory is: ', secondPassword.password)
        print('Are they the same? ', firstPassword is secondPassword)
        
        
        hashed_password = make_password("mypassword123")
        #print(hashed_password)  # Outputs a hashed version of the password


        # Verifying the hashed password
        isPasswordValid = check_password("mypassword123", hashed_password)
        print('Is the password valid? ', isPasswordValid)  # Outputs True if the password matches

        #Salting
        password = b'password1234'
        salt = bcrypt.gensalt()
        #hashWithSaltPassword = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        hashWithSaltPassword = bcrypt.hashpw(password, salt)
        print('Hash with salt password is: ', hashWithSaltPassword)
        # Verify a password
        passwordToVerify = b'password1234'

        # if bcrypt.checkpw(passwordToVerify, hashWithSaltPassword):
        #     print("Password is correct")
        # else:
        #     print("Invalid password")

        return Response(serializer.data)


    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PostListCreate(generics.ListCreateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = ([IsAuthenticatedOrReadOnly])
    filter_backends = [django_filters.rest_framework.DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['id','content']
    search_fields = ['id','content']
    ordering_fields = ['id','content', 'created_at']



    # def post(self, request):
    #     serializer = PostSerializer(data=request.data)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CommentListCreate(APIView):
    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)


    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Create your views here.
# def get_users(request):
#     try:
#         users = list(User.objects.values('id', 'username', 'email', 'created_at'))
#         return JsonResponse(users, safe=False)
#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=500)

# @csrf_exempt
# def create_user(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body)
#             user = User.objects.create_user(username="new_user", password="secure_pass123")
#             print(user.password)  # Outputs a hashed password
#             return JsonResponse({'id': user.id, 'message': 'User created successfully'}, status=201)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)

# @csrf_exempt
# def update_user(request, id):
#     if request.method == 'PUT':
#         try:
#             data = json.loads(request.body)
#             email = data['email']
#             user = User.objects.filter(id=id).first()
#             # data = UserSerializer(isinstance=user, data=request.data)
#             user.email = email
#             user.save()
#             return JsonResponse({'message': 'User updated successfully'}, status=201)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)

# @csrf_exempt
# def delete_user(request, id):
#     if request.method == 'DELETE':
#         try:
#             user = User.objects.filter(id=id).first()
#             user.delete()
#             #User.objects.delete(id=id)
#             return JsonResponse({'message': 'User deleted successfully'}, status=200)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)


