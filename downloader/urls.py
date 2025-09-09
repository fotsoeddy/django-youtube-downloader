from django.urls import path
from .views import HomeView, LoginView, SignupView, LogoutView, DownloadView, DownloadFileView, MyDownloadsView

urlpatterns = [
    path('', HomeView.as_view(), name='home'),
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('download/', DownloadView.as_view(), name='download'),
    path('download_file/', DownloadFileView.as_view(), name='download_file'),
    path('my_downloads/', MyDownloadsView.as_view(), name='my_downloads'),
]