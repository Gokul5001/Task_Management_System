from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RegisterView, LoginView, TaskListCreateView, TaskDetailView, AdminCreateUserView, UserRoleAssignmentView, AdminRegisterView,AdminTeamView

router = DefaultRouter()
router.register(r'assign_role', UserRoleAssignmentView, basename='assign_role')

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('tasks/', TaskListCreateView.as_view(), name='task_list_create'),
    path('tasks/<int:pk>/', TaskDetailView.as_view(), name='task_detail'),
    path('create_user/', AdminCreateUserView.as_view(), name='create_user'),
    path('admin/register/', AdminRegisterView.as_view(), name='admin-register'),
    path('admin/team/', AdminTeamView.as_view(), name='admin-team'),
    path('', include(router.urls)),
]
