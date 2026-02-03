import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"), session_cookie="python_session", same_site='lax', https_only=False)

oauth = OAuth()
oauth.register(
    name='my_auth_server',
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET"),
    server_metadata_url=f'{os.getenv("ISSUER_URL")}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile read',
        'code_challenge_method': 'S256'  # Enable PKCE
    },
)

@app.get("/")
async def home(request: Request):
    user = request.session.get('user')
    if user:
        return HTMLResponse(f"<h1>Welcome {user['sub']}</h1><pre>{json.dumps(user, indent=2)}</pre><a href='/logout'>Logout</a>")
    return HTMLResponse("<h1>Home</h1><a href='/login'>Login with OAuth2</a>")

@app.get("/login")
async def login(request: Request):
    redirect_uri = os.getenv("REDIRECT_URI")
    return await oauth.my_auth_server.authorize_redirect(request, redirect_uri)

@app.get("/code/callback")
async def callback(request: Request):
    token = await oauth.my_auth_server.authorize_access_token(request)
    user = token.get('userinfo')
    if not user:
        user = token.get('id_token') # fallback if userinfo is not returned or handled automatically
        # Authlib handles ID token validation and claims extraction automatically
        user = oauth.my_auth_server.parse_id_token(request, token)
        
    request.session['user'] = dict(user)
    return RedirectResponse(url='/')

@app.get("/logout")
async def logout(request: Request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=7700)
