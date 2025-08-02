from django.shortcuts import render, redirect
from django.http import JsonResponse
from openai import OpenAI
from django.contrib import auth
from django.contrib.auth.models import User
from .models import Chat
from django.utils import timezone
from django.contrib.auth.decorators import login_required

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key="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",  # Use env var in production
)

def ask_openai(message):
    try:
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1-0528-qwen3-8b:free",
            messages=[
                {"role": "user", "content": message}
            ],
            extra_headers={
                "HTTP-Referer": "http://127.0.0.1:8000",
                "X-Title": "DjangoChatBot",
            },
            extra_body={}
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error: {str(e)}"

@login_required(login_url='login')
def chatbot(request):
    chats = Chat.objects.filter(user=request.user)
    if request.method == 'POST':
        message = request.POST.get('message')
        response = ask_openai(message)

        chat = Chat(user=request.user, message=message, response=response, created_at=timezone.now())
        chat.save()
        return JsonResponse({'message': message, 'response': response})
    return render(request, 'chatbot.html', {'chats': chats})

def login(request):
    if request.user.is_authenticated:
        return redirect('chatbot')

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(request, username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('chatbot')
        else:
            return render(request, 'login.html', {'error_message': 'Invalid username or password'})
    return render(request, 'login.html')

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if password1 == password2:
            try:
                user = User.objects.create_user(username=username, email=email, password=password1)
                user.save()
                auth.login(request, user)
                return redirect('chatbot')
            except:
                return render(request, 'register.html', {'error_message': 'Error creating account'})
        else:
            return render(request, 'register.html', {'error_message': "Passwords don't match"})
    return render(request, 'register.html')

def logout(request):
    auth.logout(request)
    return redirect('login')
