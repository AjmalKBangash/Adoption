from django.shortcuts import render
from .app import add

# THIS IS EXAMPLE FUNCTION JUST DEFINED FOR PRACTICE 
def adoption_view(request):
    add.delay(2,2)
    return render(request, 'adoption_app/adoption.html')  # Replace 'adoption.html' with the name of your template
