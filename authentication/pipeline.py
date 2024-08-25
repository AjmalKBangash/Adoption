# authentication/pipeline.py
from rest_framework.response import Response
# from .views import complete_social_login
from .views import generate_jwt_token

def complete_social_login(strategy, details, user=None, *args, **kwargs):
    if user:
        # Generate JWT tokens
        tokens = generate_jwt_token(user)
        
        # Store the tokens in the session or return as needed
        strategy.session_set('jwt_tokens', tokens)
        
        return Response(tokens)
