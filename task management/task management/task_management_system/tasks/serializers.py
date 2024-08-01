from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Task
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, RefreshToken

User = get_user_model()

class EmailTokenObtainPairSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = User.objects.filter(email=email).first()
        if user is not None and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            return {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        raise serializers.ValidationError('Invalid email or password')

class UserSerializer(serializers.ModelSerializer):
    team_leader = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='team_leader'),
        required=False,
        allow_null=True
    )

    class Meta:
        model = User
        fields = ['email', 'role', 'is_active', 'is_staff', 'team_leader']
    
    def validate(self, attrs):
        role = attrs.get('role')
        team_leader = attrs.get('team_leader')

        if role == 'team_member' and not team_leader:
            raise serializers.ValidationError('Team members must have a team leader assigned.')

        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
    def update(self, instance, validated_data):
        instance.email = validated_data.get('email', instance.email)
        instance.role = validated_data.get('role', instance.role)
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.is_staff = validated_data.get('is_staff', instance.is_staff)
        instance.team_leader = validated_data.get('team_leader', instance.team_leader)
        instance.save()
        return instance

class TaskSerializer(serializers.ModelSerializer):
    assigned_to = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    created_by = serializers.ReadOnlyField(source='created_by.email')
    updated_by = serializers.ReadOnlyField(source='updated_by.email')

    class Meta:
        model = Task
        fields = ['title', 'description', 'assigned_to', 'created_by', 'updated_by', 'created_at', 'updated_at', 'status']

    def validate_assigned_to(self, value):
        request = self.context.get('request')
        if request and request.user:
            user = request.user
            if user.is_admin() and not value.is_team_leader():
                raise serializers.ValidationError("Admin can only assign tasks to team leaders.")
            if user.is_team_leader() and not value.is_team_member():
                raise serializers.ValidationError("Team leaders can only assign tasks to team members.")
        return value

class AdminRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            role='admin',
            is_staff=True,
            is_superuser=True
        )
        return user
