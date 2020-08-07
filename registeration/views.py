from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render,redirect
from django.template.loader import render_to_string
from django.views.generic import View
from django.contrib.auth.models import User
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth import authenticate, login, logout

from django.conf import settings
from django.core.mail import EmailMessage
from django.utils.encoding import force_text, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import account_activation_token
# Create your views here.

class HomeView(View):
    def get(self,request):
        return render(request,'home.html')


class RegisterationView(View):
    def get(self,request):
        return render(request,'auth/register.html')

    def post(self,request):

        context = {
            'data': request.POST,
            'has_error': False
        }

        username = request.POST.get('username')
        fullname = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if username == '':
            messages.add_message(request, messages.ERROR, 'provide a valid username')
            context['has_error'] = True
        if not validate_email(email):
            messages.add_message(request, messages.ERROR, 'provide a valid email')
            context['has_error'] = True
        if fullname == '':
            messages.add_message(request, messages.ERROR, 'fullname are required')
            context['has_error'] = True
        if password == '' or password2 == '':
            messages.add_message(request, messages.ERROR, 'Passwords are required')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request, messages.ERROR, 'Passwords do not match')
            context['has_error'] = True
        if User.objects.filter(email=email).exists():
            messages.add_message(request, messages.ERROR, 'email is taken,chose another one')
            context['has_error'] = True
        if User.objects.filter(username=username).exists():
            messages.add_message(request, messages.ERROR, 'username is taken,chose another one')
            context['has_error'] = True
        if context['has_error']:
            return render(request, 'auth/register.html', context, status=400)

        new_user = User.objects.create_user(username=username, email=email)
        new_user.set_password(password)
        new_user.first_name = fullname
        new_user.last_name = fullname
        new_user.is_active = True
        new_user.is_staff=True
        new_user.save()

        current_site = get_current_site(request)
        email_subject = 'Activate Your Account'
        message = render_to_string('auth/activate_account.html', {
            'user': new_user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(new_user.pk)),
            'token': account_activation_token.make_token(new_user),
        })
        email_message=EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email],


        )
        email_message.send()
        messages.add_message(request, messages.SUCCESS, 'Account created successfully,please visit your Email to '
                                                    'verify your Account')
        return render(request,'auth/password_reset_complete.html')


class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == '':
            messages.add_message(request, messages.ERROR, 'username are required')
            context['has_error'] = True
        if password == '':
            messages.add_message(request, messages.ERROR, 'Password is required')
            context['has_error'] = True

        user = authenticate(request, username=username, password=password)
        if not context['has_error'] and not user:
            messages.add_message(request, messages.ERROR, 'Incorrect login credentials')
            context['has_error'] = True
        if context['has_error']:
            return render(request, 'auth/login.html', context, status=401)
        login(request, user)
        return redirect('home')

class VerificationView(View):

    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request,messages.INFO, "Account has been activated,you may login now")
            return render(request,'auth/user_change_password.html', context={'uidb64': uidb64, 'token': token}, status=401)
        return render(request, "auth/invalid_activation.html", status=401)


class RequestResetLinkView(View):
    def get(self, request):
        return render(request, 'auth/reset_password.html')

    def post(self, request):
        context = {
            'data': request.POST
        }
        email = request.POST.get('email')
        if not validate_email(email):
            messages.add_message(request, messages.ERROR, 'please provide a valid email')
            return render(request, 'auth/reset_password.html', context, status=400)

        new_user = User.objects.filter(email=email).first()
        if not new_user:
            messages.add_message(request, messages.ERROR, 'Details not found,please consider a signup')
            return render(request, 'auth/reset_password.html', context, status=404)
        current_site = get_current_site(request)
        email_subject = 'Activate Your Account'
        message = render_to_string('auth/finish_reset.html', {
            'user': new_user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(new_user.pk)),
            'token': account_activation_token.make_token(new_user),
        })
        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]
        )
        email_message.send()
        messages.add_message(request, messages.INFO, 'We have sent you an email with a link to reset your password')
        return render(request, 'auth/reset_password.html', context)


class CompletePasswordChangeView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is None or not account_activation_token.check_token(user, token):
            messages.add_message(request, messages.WARNING, 'Link is no longer valid,please request a new one')
            return render(request, 'auth/reset_password.html', status=401)
        return render(request, 'auth/change_password.html', context={'uidb64': uidb64, 'token': token})

    def post(self, request, uidb64, token):
        context = {'uidb64': uidb64, 'token': token}
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            password = request.POST.get('password')
            password2 = request.POST.get('password2')
            if len(password) < 6:
                messages.add_message(request, messages.ERROR, 'Password should be at least 6 characters long')
                return render(request, 'auth/change_password.html', context, status=400)
            if password != password2:
                messages.add_message(request, messages.ERROR, 'Passwords must match')
                return render(request, 'auth/change_password.html', context, status=400)
            user.set_password(password)
            user.save()
            messages.add_message(request, messages.INFO, 'Password changed successfully,login with your new password')
            return redirect('login')
        except DjangoUnicodeDecodeError:
            messages.add_message(request, messages.ERROR, 'Something went wrong,you could not update your password')
            return render(request, 'auth/change_password.html', context, status=401)



class LogoutView(View):
    def get(self, request):
        messages.add_message(request, messages.SUCCESS, 'You have successfully logged out')
        logout(request)
        return redirect('login')
