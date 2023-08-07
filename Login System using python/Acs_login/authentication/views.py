from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from captcha.fields import ReCaptchaField
from acs_login import settings
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import generate_token
from django.contrib.auth.hashers import make_password, check_password


# Creating views here.

captcha = ReCaptchaField()

def index(request):
    return render(request, "authentication/register.html")

def home(request):
    return render(request, "authentication/index.html")

#for registration
def register(request):
    if request.method == "POST":
        username = request.POST['username']
        fullname = request.POST['fullname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        captcha_response = request.POST.get('g-recaptcha-response')
        try:
            captcha.clean(captcha_response)
        except ValidationError:
            messages.error(request, "Invalid reCAPTCHA. Please try again.")
            return redirect('register')

        #Validate User
        if User.objects.filter(username=username):
            messages.error(request, 'Username already exist. Try new username')
            return redirect('register')

        if User.objects.filter(email=email):
            messages.error(request, 'Email already exist!!')
            return redirect('register')

        if len(username)>10:
            messages.error(request, 'Username must be less than 10 characters')
            return redirect('register')

        if not (any(c.isalpha() for c in username) and any(c.isdigit() for c in username)):
            messages.error(request, 'Username must contain both letters and numbers')
            return redirect('register')


        # Validate password

        try:
            validate_password(pass1, user=User)
        except ValidationError as error:
            messages.error(request, error.messages[0])
            return redirect('register')

        # Check if passwords match
        if pass1 != pass2:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        # Create user
        hashed_password = make_password(pass1)
        myuser = User.objects.create(username=username,email=email,password=hashed_password,is_active=False)

        messages.success(request, "Congratulations!! Your account is registered. Confirmation link is sent to your email !! Please verify your email to log in.")

        #Confirmation of the email
        current_site = get_current_site(request)
        email_subject = "Confirm your email for Security Login Portal!!"
        message2 = render_to_string('authentication/email_confirmation.html', {
            'name' : myuser.username,
            'domain' : current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token' : generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [email],
        )
        email.fail_silently = True
        email.send()

        return redirect('confirm')

    return render(request, "authentication/register.html")


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        messages.success(request, "Congratulations!! Your email is verified. please login now !!")
        return redirect('loginpage')
    else:
        return render(request, 'authentication/activation_failed.html')


def loginpage(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['pass1']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                messages.success(request, f"Welcome {username}!")
                return render(request, "authentication/index.html", {'username': username})
            else:
                messages.error(request, "Your account is not activated yet. Please check your email to activate it.")
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, "authentication/loginpage.html")


def reset_form(request):
    if request.method == "POST":
        email = request.POST['email']
        email_obj = User.objects.get(email=email)
        messages.success(request, "Password link is sent to your email !! Please check email and verify it.")

        #confirm email
        current_site = get_current_site(request)
        email_subject = "Forgotten your password?"
        message3 = render_to_string('authentication/password_reset_email.html', {
            'name' : email_obj.username,
            'domain' : current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(email_obj.pk)),
            'token' : generate_token.make_token(email_obj)
        })
        email = EmailMessage(
            email_subject,
            message3,
            settings.EMAIL_HOST_USER,
            [email_obj.email],
        )
        email.fail_silently = True
        email.send()

        return redirect('reset_link')
    else:
        return render(request, 'authentication/reset_form.html')


def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        email = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        email = None

    if email is not None and generate_token.check_token(email, token):

        messages.success(request, "Email confirmed! Change your password now")
        return render(request, 'authentication/password_reset_confirm.html')
    else:
        return render(request, 'authentication/activation_failed.html')
    
def password_reset_complete(request):
    if request.method == 'POST':
        email = request.POST['email']
        password1 = request.POST['newpass']
        password2 = request.POST['newpass2']

        # Check if passwords match
        user = User.objects.get(email=email)
        if user.check_password(password1):
            messages.error(request, "You can not enter old password. Try new one") 
            return redirect('password_reset_complete')

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('password_reset_complete')

        try:
            validate_password(password1, user=User)
        except ValidationError as error:
            messages.error(request, error.messages[0])
            return redirect('password_reset_complete')

        
        user.set_password(password1)
        user.save()
        messages.success(request, 'Your password has been changed successfully')
        return redirect('loginpage')

    return render(request, 'authentication/password_reset_confirm.html')

def confirm(request):
    return render(request, "authentication/confirm.html")


def about(request):
    return render(request, "authentication/about.html")


def reset_link(request):
    return render(request, "authentication/reset_link.html")

def loggedout(request):
    logout(request)
    return redirect('home')