import os
import uuid
from django.views.generic import View, TemplateView
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.http import FileResponse, JsonResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods
import yt_dlp
from .models import DownloadedVideo

class HomeView(TemplateView):
    template_name = 'index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Show public or sample downloads for unauthenticated users
        if self.request.user.is_authenticated:
            context['downloads'] = self.request.user.downloads.all().order_by('-downloaded_at')[:3]
        else:
            # Sample public downloads or latest public ones (you can modify this)
            context['downloads'] = DownloadedVideo.objects.filter(user__isnull=False).order_by('-downloaded_at')[:3] if DownloadedVideo.objects.exists() else []
        context['is_authenticated'] = self.request.user.is_authenticated
        return context

class LoginView(View):
    template_name = 'login.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return JsonResponse({'success': True, 'redirect_url': '/'})
        return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=400)

class SignupView(View):
    template_name = 'signup.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            return JsonResponse({'success': False, 'error': 'Passwords do not match'}, status=400)

        if User.objects.filter(username=username).exists():
            return JsonResponse({'success': False, 'error': 'Username already exists'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'error': 'Email already exists'}, status=400)

        try:
            user = User.objects.create_user(username=username, email=email, password=password1)
            login(request, user)
            return JsonResponse({'success': True, 'redirect_url': '/'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('home')

class DownloadView(View):
    """Handle URL input and show format selection - require login if not authenticated"""
    template_name = 'download.html'

    def get(self, request):
        return render(request, self.template_name)

    @method_decorator(csrf_exempt, name='dispatch')
    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'success': False, 'error': 'Please login to download', 'redirect_url': '/login/'}, status=401)

        video_url = request.POST.get('video_url')
        try:
            ydl_opts = {
                'quiet': True,
                'skip_download': True,
                'format': 'bestvideo+bestaudio/best',
            }
            if os.path.exists('cookies.txt'):
                ydl_opts['cookies'] = 'cookies.txt'

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(video_url, download=False)

            video_title = info.get('title')
            thumbnail_url = info.get('thumbnail')
            formats = info.get('formats', [])

            # Filter for mp4 video formats
            video_streams = [f for f in formats if f.get('vcodec') != 'none' and f.get('ext') == 'mp4']
            audio_streams = [f for f in formats if f.get('vcodec') == 'none' and f.get('acodec') != 'none']
            audio_stream = audio_streams[0] if audio_streams else None

            return render(request, self.template_name, {
                'video_title': video_title,
                'thumbnail_url': thumbnail_url,
                'audio_stream': audio_stream,
                'video_streams': video_streams,
                'video_url': video_url,
                'error': None
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

class DownloadFileView(LoginRequiredMixin, View):
    @method_decorator(csrf_exempt, name='dispatch')
    def post(self, request):
        video_url = request.POST.get('video_url')
        format_id = request.POST.get('format_id')
        temp_filename = f'temp_{uuid.uuid4()}.mp4'

        ydl_opts = {
            'format': f'{format_id}+bestaudio/best',
            'outtmpl': temp_filename,
            'quiet': True,
            'merge_output_format': 'mp4',
        }
        if os.path.exists('cookies.txt'):
            ydl_opts['cookies'] = 'cookies.txt'

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(video_url, download=True)

            # Save to history
            DownloadedVideo.objects.create(
                user=request.user,
                title=info.get('title', 'Unknown'),
                url=video_url,
                thumbnail_url=info.get('thumbnail'),
                format_id=format_id
            )

            response = FileResponse(
                open(temp_filename, 'rb'),
                as_attachment=True,
                filename=f"{info.get('title', 'video')}.mp4"
            )
            response['Content-Disposition'] = f'attachment; filename="{info.get("title", "video")}.mp4"'

            # Clean up temp file after response
            def cleanup(response):
                try:
                    os.remove(temp_filename)
                except:
                    pass
                return response
            response = cleanup(response)
            return response
        except Exception as e:
            # Clean up if file exists
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

class MyDownloadsView(LoginRequiredMixin, TemplateView):
    template_name = 'my_downloads.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['downloads'] = self.request.user.downloads.all().order_by('-downloaded_at')
        return context