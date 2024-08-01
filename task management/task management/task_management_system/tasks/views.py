from rest_framework import generics, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model
from .models import Task
from .serializers import UserSerializer, EmailTokenObtainPairSerializer, TaskSerializer, AdminRegisterSerializer

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        if not user.is_admin():
            raise permissions.PermissionDenied("Only admins can create new users.")
        serializer.save()

class LoginView(TokenObtainPairView):
    serializer_class = EmailTokenObtainPairSerializer

class AdminCreateUserView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        role = serializer.validated_data.get('role')
        team_leader = serializer.validated_data.get('team_leader')

        if role == 'team_member' and not team_leader:
            return Response({'error': 'Team members must have a team leader assigned.'}, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
    
class AdminTeamView(generics.GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]

    def get(self, request, *args, **kwargs):
        team_leaders = User.objects.filter(role='team_leader')
        team_members = User.objects.filter(role='team_member')

        team_leader_serializer = self.get_serializer(team_leaders, many=True)
        team_member_serializer = self.get_serializer(team_members, many=True)

        return Response({
            'team_leaders': team_leader_serializer.data,
            'team_members': team_member_serializer.data,
        })

# views.py

from rest_framework import generics, permissions
from .models import Task, User
from .serializers import TaskSerializer

class TaskListCreateView(generics.ListCreateAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_admin():
            return Task.objects.all()
        elif user.is_team_leader():
            return Task.objects.filter(assigned_to__team_leader=user)
        elif user.is_team_member():
            return Task.objects.filter(assigned_to=user)
        return Task.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        assigned_to_id = self.request.data.get('assigned_to')

        if assigned_to_id is None:
            raise serializer.ValidationError("The 'assigned_to' field is required.")

        try:
            assigned_to_user = User.objects.get(id=assigned_to_id)
        except User.DoesNotExist:
            raise serializer.ValidationError("The 'assigned_to' user does not exist.")

        # Admin can assign tasks to team leaders
        if user.is_admin:
            if not assigned_to_user.is_team_leader():
                raise permissions.PermissionDenied("Admin can only assign tasks to team leaders.")
        
        # Team leaders can assign tasks to team members
        elif user.is_team_leader():
            if not assigned_to_user.is_team_member():
                raise permissions.PermissionDenied("Team leaders can only assign tasks to team members.")
        
        else:
            raise permissions.PermissionDenied("Only admins and team leaders can create tasks.")

        serializer.save(created_by=user, updated_by=user, assigned_to=assigned_to_user)

class TaskDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_update(self, serializer):
        user = self.request.user
        task = self.get_object()

        if user.is_admin or (user.is_team_leader and task.assigned_to.team_leader == user):
            serializer.save(updated_by=user)
        else:
            raise permissions.PermissionDenied("Only admins or the assigned team leader can update this task.")

class UserRoleAssignmentView(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def update(self, request, pk=None):
        if not request.user.is_admin:
            return Response({'detail': 'Only admins can assign roles.'}, status=status.HTTP_403_FORBIDDEN)

        user = User.objects.get(pk=pk)
        role = request.data.get('role')
        if role not in dict(User.ROLE_CHOICES).keys():
            return Response({'detail': 'Invalid role.'}, status=status.HTTP_400_BAD_REQUEST)

        user.role = role
        user.save()
        return Response(UserSerializer(user).data)

class AdminRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = AdminRegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {
                "user": AdminRegisterSerializer(user, context=self.get_serializer_context()).data,
                "message": "Admin registered successfully. You can now log in.",
            },
            status=status.HTTP_201_CREATED,
        )
