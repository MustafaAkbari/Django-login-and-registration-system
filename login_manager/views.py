from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.shortcuts import get_current_site
from django.contrib import messages
from django.db import transaction
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from login_system import settings
from .tokens import generate_token

# Create your views here.

def home(request):
    return render(request, 'index.html')

def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        # Using Django's authenticate function to verify the credentials
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # If authentication is successful, log in the user
            login(request, user)
            first_name = user.first_name
            messages.success(request, f'Dear {first_name} you have successfully logged in!')
            return render(request, 'index.html', {'name': first_name})
        else:
            # If authentication fails, display an error message and redirect back to the login page
            messages.error(request, 'Invalid username or password. Please try again!')
            return redirect('signin')
    return render(request, 'signin.html')

@transaction.atomic()
def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']
        confirmpassword = request.POST['confirmpassword']

        # check if passwrods match
        if password != confirmpassword:
            messages.error(request, 'Passwrods do not match!')
            return redirect('signup')

        # check if username exists
        if User.objects.filter(username=username).exists():
            messages.error(request, 'This username is already taken!')
            return redirect('signup')

        # check if email exists
        if User.objects.filter(email=email).exists():
            messages.error(request, 'This email is already in use!')
            return redirect('signup')

        # create a user
        user = User.objects.create_user(username=username, email=email, password=password, first_name=firstname, last_name=lastname)
        user.is_active = False
        messages.success(request, f'Dear {user.first_name} your account successfully created, we have sent you a confirmation link,\
                        please confrim your email in order to active your account.')

        # Sending Email
        subject = 'Welcome to the django login system!'
        message = f"Hello {user.first_name} ! \nThank you for visiting our website\nWe have send you a confirmation email\n" \
                  "Please confirm your email in order to activate your account\nThanking you\nMustafa Akbari"
        from_email = settings.EMAIL_HOST_USER
        to = [user.email]
        send_mail(subject=subject, message=message, from_email=from_email, recipient_list=to, fail_silently=False)

        # Sending email confirmation
        current_site = get_current_site(request)
        confirmation_subject = 'Please confirm your email address in order to login!'
        confirmation_message = render_to_string('email_confirmation.html', {
            'name': user.first_name,
            'domain': current_site.domain,
            'userid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })
        confirmation_email = EmailMessage(
            subject= confirmation_subject,
            body= confirmation_message,
            from_email= settings.EMAIL_HOST_USER,
            to=[user.email]
        )
        confirmation_email.send()
        return redirect('signin')
    return render(request, 'signup.html')

def signout(request):
    logout(request)
    messages.success(request, 'You have logged out from your account!')
    return redirect('signup')

def activate(request, uidb64, token):
    # Try to decode the user ID from base64 representation.
    try:
        # Decode the base64 user ID and convert to text.
        user_id = force_str(urlsafe_base64_decode(uidb64))
        # Retrieve the user object from the database using the decoded user ID.
        user = User.objects.get(pk=user_id)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        # Handle exceptions (e.g., invalid base64 or user not found).
        # Set user to None in case of errors.
        user = None

    # Check if the user is not None and the token is valid.
    if user is not None and generate_token.check_token(user=user, token=token):
        # If the user and token are valid, activate the user account.
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request, f'Your account has been activated, Welcome to your dashboar {user.first_name}')
        return redirect('home')
    else:
        return render(request, 'activation_failed.html')
