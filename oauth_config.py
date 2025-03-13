from authlib.integrations.flask_client import OAuth
from config_settings import Config

oauth = OAuth()

def init_oauth(app):
    """Initialize OAuth with Google authentication."""
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=Config.GOOGLE_CLIENT_ID,
        client_secret=Config.GOOGLE_CLIENT_SECRET,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        access_token_url='https://oauth2.googleapis.com/token',
        access_token_params=None,
        refresh_token_url=None,
        redirect_uri=Config.GOOGLE_REDIRECT_URI,
        client_kwargs={'scope': 'openid email profile'},
    )
  