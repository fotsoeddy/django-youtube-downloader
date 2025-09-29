import base64
import os
import tempfile
import uuid
from django.conf import settings
import logging
from django.views.generic import View, TemplateView
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.http import FileResponse, JsonResponse, HttpResponseRedirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import yt_dlp
from .models import DownloadedVideo

# Configure logger with detailed formatting
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s %(process)d %(thread)d %(message)s'
)
logger = logging.getLogger('downloader')

class HomeView(TemplateView):
    template_name = 'index.html'

    def get_context_data(self, **kwargs):
        logger.debug("Entering HomeView.get_context_data")
        context = super().get_context_data(**kwargs)
        
        if self.request.user.is_authenticated:
            downloads = self.request.user.downloads.all().order_by('-downloaded_at')[:3]
            public_downloads = DownloadedVideo.objects.exclude(user=self.request.user).order_by('-downloaded_at')[:3]
            logger.info(f"User {self.request.user.username} accessed home page with {len(downloads)} user downloads and {len(public_downloads)} public downloads")
            context['downloads'] = downloads
        else:
            downloads = []
            public_downloads = DownloadedVideo.objects.filter(user__isnull=False).order_by('-downloaded_at')[:3] if DownloadedVideo.objects.exists() else []
            logger.info(f"Unauthenticated user accessed home page with {len(public_downloads)} public downloads")
        
        context['public_downloads'] = public_downloads
        context['is_authenticated'] = self.request.user.is_authenticated
        logger.debug("Exiting HomeView.get_context_data with context: %s", context)
        return context

class LoginView(View):
    template_name = 'login.html'

    def get(self, request):
        logger.debug("Entering LoginView.get")
        if request.user.is_authenticated:
            logger.info(f"Authenticated user {request.user.username} redirected from login to home")
            return redirect('home')
        logger.info("Login page accessed via GET")
        logger.debug("Exiting LoginView.get")
        return render(request, self.template_name)

    def post(self, request):
        logger.debug("Entering LoginView.post")
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        logger.info(f"Login attempt for username: {username}")

        if not username or not password:
            error_msg = 'Username and password are required'
            logger.warning(f"Login failed: {error_msg}")
            if is_ajax:
                logger.debug("Returning JSON response for failed login (missing credentials)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering login template with error")
                return render(request, self.template_name, {'error': error_msg})

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            logger.info(f"Successful login for user: {username}")
            if is_ajax:
                logger.debug("Returning JSON response for successful login")
                return JsonResponse({'success': True, 'redirect_url': '/'})
            else:
                logger.debug("Redirecting to home after successful login")
                return redirect('home')
        else:
            error_msg = 'Invalid username or password'
            logger.warning(f"Login failed for {username}: {error_msg}")
            if is_ajax:
                logger.debug("Returning JSON response for failed login (invalid credentials)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering login template with error")
                return render(request, self.template_name, {'error': error_msg})

class SignupView(View):
    template_name = 'signup.html'

    def get(self, request):
        logger.debug("Entering SignupView.get")
        if request.user.is_authenticated:
            logger.info(f"Authenticated user {request.user.username} redirected from signup to home")
            return redirect('home')
        logger.info("Signup page accessed via GET")
        logger.debug("Exiting SignupView.get")
        return render(request, self.template_name)

    def post(self, request):
        logger.debug("Entering SignupView.post")
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        logger.info(f"Signup attempt for username: {username}, email: {email}")

        if not all([username, email, password1, password2]):
            error_msg = 'All fields are required'
            logger.warning(f"Signup failed: {error_msg}")
            if is_ajax:
                logger.debug("Returning JSON response for failed signup (missing fields)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering signup template with error")
                return render(request, self.template_name, {'error': error_msg})

        if password1 != password2:
            error_msg = 'Passwords do not match'
            logger.warning(f"Signup failed for {username}: {error_msg}")
            if is_ajax:
                logger.debug("Returning JSON response for failed signup (password mismatch)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering signup template with error")
                return render(request, self.template_name, {'error': error_msg})

        if User.objects.filter(username=username).exists():
            error_msg = 'Username already exists'
            logger.warning(f"Signup failed: {error_msg} for {username}")
            if is_ajax:
                logger.debug("Returning JSON response for failed signup (username exists)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering signup template with error")
                return render(request, self.template_name, {'error': error_msg})

        if User.objects.filter(email=email).exists():
            error_msg = 'Email already exists'
            logger.warning(f"Signup failed: {error_msg} for {email}")
            if is_ajax:
                logger.debug("Returning JSON response for failed signup (email exists)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering signup template with error")
                return render(request, self.template_name, {'error': error_msg})

        if len(password1) < 8:
            error_msg = 'Password must be at least 8 characters long'
            logger.warning(f"Signup failed for {username}: {error_msg}")
            if is_ajax:
                logger.debug("Returning JSON response for failed signup (password too short)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering signup template with error")
                return render(request, self.template_name, {'error': error_msg})

        try:
            user = User.objects.create_user(username=username, email=email, password=password1)
            login(request, user)
            logger.info(f"Successful signup and login for user: {username}")
            if is_ajax:
                logger.debug("Returning JSON response for successful signup")
                return JsonResponse({'success': True, 'redirect_url': '/'})
            else:
                logger.debug("Redirecting to home after successful signup")
                return redirect('home')
        except Exception as e:
            error_msg = f'An error occurred: {str(e)}'
            logger.error(f"Signup error for {username}: {str(e)}", exc_info=True)
            if is_ajax:
                logger.debug("Returning JSON response for failed signup (exception)")
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            else:
                logger.debug("Rendering signup template with error")
                return render(request, self.template_name, {'error': error_msg})

class LogoutView(View):
    def get(self, request):
        logger.debug("Entering LogoutView.get")
        username = request.user.username if request.user.is_authenticated else 'anonymous'
        logout(request)
        logger.info(f"User {username} logged out")
        logger.debug("Exiting LogoutView.get")
        return redirect('home')

class DownloadView(View):
    template_name = 'download.html'

    def get(self, request):
        logger.debug("Entering DownloadView.get")
        if not request.user.is_authenticated:
            logger.info("Unauthenticated user redirected to login from download page")
            return redirect('login')
        context = request.session.get('last_video_info', {'error': None})
        logger.info(f"User {request.user.username} accessed download page via GET with context: {context}")
        logger.debug("Exiting DownloadView.get")
        return render(request, self.template_name, context)

    @method_decorator(csrf_exempt, name='dispatch')
    def post(self, request):
        logger.debug("Entering DownloadView.post")
        if not request.user.is_authenticated:
            logger.warning("Unauthenticated user attempted to download")
            return JsonResponse({'success': False, 'error': 'Please login to download', 'redirect_url': '/login/'}, status=401)

        video_url = request.POST.get('video_url')
        if not video_url:
            logger.warning("Download attempt failed: No video URL provided")
            return JsonResponse({'success': False, 'error': 'No video URL provided'}, status=400)

        logger.info(f"Processing video URL: {video_url} for user {request.user.username}")

        # Create temporary cookies file from base64 env
        cookies_file_path = None
        try:
            yt_cookies_b64 = os.environ.get('YT_COOKIES_B64')
            if yt_cookies_b64:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp_file:
                    cookies_file_path = tmp_file.name
                    tmp_file.write(base64.b64decode(yt_cookies_b64))
                logger.debug(f"Temporary cookies file created at {cookies_file_path}")
        except Exception as e:
            logger.error(f"Failed to decode YT_COOKIES_B64: {e}")

        try:
            ydl_opts = {
                'quiet': True,
                'skip_download': True,
                'format': 'bestvideo+bestaudio/best',
            }
            if cookies_file_path and os.path.exists(cookies_file_path):
                ydl_opts['cookiefile'] = cookies_file_path
                logger.debug(f"Using cookies from {cookies_file_path}")
            else:
                logger.warning("No cookies file found; YouTube downloads may fail")

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                logger.debug(f"Extracting info for URL: {video_url}")
                info = ydl.extract_info(video_url, download=False)

            video_title = info.get('title', 'Unknown Video')
            thumbnail_url = info.get('thumbnail') or (info.get('thumbnails', [{}])[0].get('url') if info.get('thumbnails') else None)
            formats = info.get('formats', [])

            video_streams = [f for f in formats if f.get('vcodec') != 'none' and f.get('ext') == 'mp4']
            audio_streams = [f for f in formats if f.get('vcodec') == 'none' and f.get('acodec') != 'none']
            audio_stream = audio_streams[0] if audio_streams else None

            context = {
                'video_title': video_title,
                'thumbnail_url': thumbnail_url,
                'audio_stream': audio_stream,
                'video_streams': video_streams,
                'video_url': video_url,
                'error': None
            }
            request.session['last_video_info'] = context
            request.session.modified = True

            if not video_streams and not audio_stream:
                context['error'] = 'No downloadable formats available for this video.'
                return render(request, self.template_name, context)

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'video_title': video_title,
                    'thumbnail_url': thumbnail_url,
                    'audio_stream': {
                        'format_id': audio_stream.get('format_id') if audio_stream else None,
                        'abr': audio_stream.get('abr', 'Unknown') if audio_stream else 'Unknown',
                        'ext': audio_stream.get('ext', 'mp3') if audio_stream else 'mp3'
                    } if audio_stream else None,
                    'video_streams': [
                        {
                            'format_id': stream.get('format_id', 'unknown'),
                            'height': stream.get('height', 'Unknown'),
                            'format_note': stream.get('format_note', ''),
                            'tbr': stream.get('tbr', 'Unknown')
                        } for stream in video_streams
                    ],
                    'video_url': video_url,
                    'redirect_url': '/download/'
                })

            return render(request, self.template_name, context)

        except Exception as e:
            logger.error(f"Error processing video URL {video_url}: {str(e)}", exc_info=True)
            context = {'error': f'Failed to process video: {str(e)}'}
            request.session['last_video_info'] = context
            request.session.modified = True
            return render(request, self.template_name, context)

        finally:
            # Clean up temporary cookies file
            if cookies_file_path and os.path.exists(cookies_file_path):
                os.remove(cookies_file_path)
                logger.debug(f"Temporary cookies file {cookies_file_path} removed")
class DownloadFileView(LoginRequiredMixin, View):
    @method_decorator(csrf_exempt, name='dispatch')
    def post(self, request):
        logger.debug("Entering DownloadFileView.post")
        video_url = request.POST.get('video_url')
        format_id = request.POST.get('format_id')

        if not video_url or not format_id:
            logger.warning(f"Download failed for user {request.user.username}: Missing video URL or format")
            return JsonResponse({'success': False, 'error': 'Missing video URL or format'}, status=400)

        temp_filename = f"temp_{uuid.uuid4()}.%(ext)s"
        logger.info(f"Starting download for user {request.user.username}: URL={video_url}, format={format_id}")

        ydl_opts = {
            'format': f'{format_id}+bestaudio/best' if format_id != 'audio_only' else format_id,
            'outtmpl': temp_filename,
            'quiet': True,
            'merge_output_format': 'mp4' if format_id != 'audio_only' else None,
        }
        if settings.YT_COOKIES_FILE and os.path.exists(settings.YT_COOKIES_FILE):
            ydl_opts['cookiefile'] = settings.YT_COOKIES_FILE
            logger.debug(f"Using cookies from {settings.YT_COOKIES_FILE}")
        else:
            logger.warning("No cookies file found, YouTube downloads may fail")

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                logger.debug(f"Downloading video: {video_url} with format {format_id}")
                info = ydl.extract_info(video_url, download=True)

            actual_filename = ydl.prepare_filename(info)
            logger.info(f"Download completed: {actual_filename}")

            # Save download history
            DownloadedVideo.objects.create(
                user=request.user,
                title=info.get('title', 'Unknown'),
                url=video_url,
                thumbnail_url=info.get('thumbnail') or (info.get('thumbnails', [{}])[0].get('url') if info.get('thumbnails') else None),
                format_id=format_id
            )
            logger.info(f"Download history saved for user {request.user.username}: {info.get('title', 'Unknown')}")

            file_ext = 'mp3' if format_id == 'audio_only' else info.get('ext', 'mp4')
            response = FileResponse(
                open(actual_filename, 'rb'),
                as_attachment=True,
                filename=f"{info.get('title', 'video')[:50]}.{file_ext}"
            )
            response['Content-Disposition'] = f'attachment; filename="{info.get('title', 'video')[:50]}.{file_ext}"'
            response['Content-Type'] = 'application/octet-stream'

            def cleanup_temp_file():
                try:
                    if os.path.exists(actual_filename):
                        os.remove(actual_filename)
                        logger.debug(f"Temporary file {actual_filename} deleted")
                except Exception as e:
                    logger.error(f"Error cleaning up temp file {actual_filename}: {str(e)}")

            response._closable = True
            original_close = response.close
            def new_close():
                cleanup_temp_file()
                if original_close:
                    original_close()
            response.close = new_close

            logger.debug("Returning FileResponse for download")
            return response

        except Exception as e:
            if 'actual_filename' in locals() and os.path.exists(actual_filename):
                try:
                    os.remove(actual_filename)
                    logger.debug(f"Temporary file {actual_filename} deleted after error")
                except:
                    pass
            logger.error(f"Download failed for user {request.user.username}: {str(e)}", exc_info=True)
            return JsonResponse({'success': False, 'error': f'Download failed: {str(e)}'}, status=400)

class MyDownloadsView(LoginRequiredMixin, TemplateView):
    template_name = 'my_downloads.html'

    def get_context_data(self, **kwargs):
        logger.debug("Entering MyDownloadsView.get_context_data")
        context = super().get_context_data(**kwargs)
        downloads = self.request.user.downloads.all().order_by('-downloaded_at')
        logger.info(f"User {self.request.user.username} accessed their downloads page with {len(downloads)} downloads")
        context['downloads'] = downloads
        logger.debug("Exiting MyDownloadsView.get_context_data")
        return context