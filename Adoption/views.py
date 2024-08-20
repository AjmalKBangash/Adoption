from django.shortcuts import render

def adoption_view(request):
    return render(request, 'adoption_app/adoption.html')  # Replace 'adoption.html' with the name of your template
