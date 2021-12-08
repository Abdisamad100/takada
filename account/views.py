from django.contrib import messages
from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.models import User, Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect


# Create your views here.
from home.decorators import unauthenticated_user


@unauthenticated_user
def register(request):
    if request.method == 'POST':

        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        username = request.POST.get('username')
        pnumber = request.POST.get('pnumber')
        password = request.POST.get('password')
        password1 = request.POST.get('password1')

        if password == password1:
            if not User.objects.filter(email=email).exists():
                if User.objects.filter(username=username).exists():
                    messages.error(request,
                                   'Magacan horaa loisticmalay! Fadlan Isticmal magac kaduwan.')
                    return redirect('register')
                else:
                    try:
                        validate_password(password)
                        user = User.objects.create(email=email, username=username)
                        user.set_password(password)
                        user.first_name = fname
                        user.last_name = lname
                        # user.userprofile.phone_number = pnumber
                        
                        user.save()
                        messages.success(request, 'waad kugulaysatay Isdiwaangalintan mahadsanid')

                        return redirect('login')

                    except ValidationError as e:
                        messages.error(request, f'Password error! {e}')
                        return redirect('register')

            else:
                messages.error(request,
                               'Emailkan horaa lo isticmalay! Fadlan Kugal Email Kale.')
                return redirect('register')
        else:
            messages.error(request, 'Passwordka aad kucelisay waa qalad!! Fadlan iskahubi marlabaad')
            return redirect('register')

    return render(request, template_name='admin_/account/register.html', context={'page': 'register'})


@unauthenticated_user
def login_(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'waad kugulaysatay inaad horeey ugaasho!')
            return redirect('home')
        else:
            messages.error(request, 'wankaxunahay Fadland iskahubi numberka sirta aah.')
            return redirect('login')
    return render(request, template_name='admin_/account/login.html', context={'page': 'login'})


def logout_(request):
    logout(request)
    return redirect('login')
