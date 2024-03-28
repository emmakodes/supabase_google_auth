import os
import time
import jwt
import reflex as rx
from .supabase__client import supabase_client
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv
from typing import List, Dict, Any

# load env
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM") 


class State(rx.State):
    auth_token: str = rx.Cookie("auth_token",secure=True)
    current_page_paths:List[Any] = []
    user_data: Dict[str, str]


    def get_user_token(self):
        """
        Retrieves a user token using OAuth authentication with Google.
        
        This method initializes the current page paths list, appends the current page's full raw path to it,
        then proceeds to sign in the user with OAuth using Google as the provider through Supabase authentication. 
        It redirects the user to the specified callback URL upon successful authentication.

        Returns:
            RedirectResponse: A redirection response object to the URL provided by the authentication process.
        """
            
        self.current_page_paths = []
        self.current_page_paths.append(self.router.page.full_raw_path)  
        res = supabase_client().auth.sign_in_with_oauth(
            {
                "provider": "google",
                "options": {
                    "redirect_to": "http://localhost:3000/callback/"   
                    },
            }
        )
        return rx.redirect(res.url)


    @rx.cached_var
    def tokeninfo(self) -> dict[str, str]:
        """
        Retrieves and decodes the user's authentication token and returns the token information.

        This method attempts to decode the authentication token stored in 'auth_token' attribute.
        If successful, it verifies the token against the provided JWT secret and audience.
        The decoded token's user metadata is stored in 'user_data' attribute.
        If the token is still valid (i.e., not expired and issued within the acceptable time frame),
        it returns the decoded token; otherwise, it returns None.

        Returns:
            dict[str, str] or None: A dictionary containing the decoded token information if valid;
                otherwise, None if the token is invalid or an error occurs during decoding.
        """
        try:
            decoded_token = jwt.decode(self.auth_token,JWT_SECRET,do_verify=True,algorithms=[JWT_ALGORITHM],audience="authenticated",leeway=1)
            self.user_data = decoded_token['user_metadata']
            return decoded_token if decoded_token["exp"] >= time.time() and decoded_token["iat"] <= time.time() else None
        except Exception as e:
            return {}


    @rx.var
    def token_is_valid(self) -> bool:
        """
        Checks if the user's authentication token is valid.

        This method checks if the authentication token stored in the 'tokeninfo' attribute exists.
        If 'tokeninfo' contains a valid decoded token, it returns True, indicating that the token is valid.
        Otherwise, it returns False, indicating that the token is either invalid or an error occurred during validation.

        Returns:
            bool: True if the authentication token is valid, False otherwise.
        """
        try:
            return bool(
                self.tokeninfo
            )
        except Exception:
            return False
    

    def redir(self) -> rx.event.EventSpec | None:
        """Redirect to the protected route."""
        if not self.is_hydrated:
            # wait until after hydration
            return State.redir()
        
        if not self.token_is_valid:
            return rx.redirect('/')

        # Find the first string that is not 'http://localhost:3000/'
        # protected_url_path = next((item for item in self.current_page_paths if item != 'http://localhost:3000/'), None)

        protected_url_path = self.current_page_paths[0]
        return rx.redirect(protected_url_path)
    

    def retrieve_access_token(self):
        raw_path_url = self.router.page.raw_path

        # Parse the URL
        parsed_url = urlparse(raw_path_url)

        # Extract the query parameters from the URL
        query_params = parse_qs(parsed_url.fragment)

        # Extract access_token and refresh_token
        access_token = query_params.get('access_token', [None])[0]
        refresh_token = query_params.get('refresh_token', [None])[0]
        self.auth_token = access_token
        return State.redir()


    def logout(self):
        """
        Logs out the user by clearing the authentication token.

        This method clears the authentication token stored in the 'auth_token' attribute,
        effectively logging out the user from the current session.

        """
        self.auth_token = ""
        


def user_info(user_data: dict) -> rx.Component:
    return rx.hstack(
        rx.avatar(
            src=user_data['picture'],
            size="5",
        ),
        rx.vstack(
            rx.heading(user_data["name"], size="5"),
            rx.text(user_data['email']),
            align_items="flex-start",
        ),
        rx.button("Logout", on_click=State.logout),
        padding="10px",
        align_items="center"
    )


def login() -> rx.Component:
    return rx.vstack(
        rx.button("Sign in with Google", on_click=State.get_user_token),
        align_items="center",
        margin_top="5px",
    )


def require_login(page: rx.app.ComponentCallable) -> rx.app.ComponentCallable:
    """Decorator to require authentication before rendering a page.

    If the user is not authenticated, then redirect to the login page.

    Args:
        page: The page to wrap.

    Returns:
        The wrapped page component.
    """
    def protected_page():
        return rx.fragment(
            rx.cond(
                State.is_hydrated,                
                rx.cond(
                    State.token_is_valid, page(), login()
                ), 
                rx.chakra.center(
                    # When this spinner mounts, it will redirect to the login page
                    rx.chakra.spinner(),
                ),
            )
        )

    protected_page.__name__ = page.__name__
    return protected_page


@rx.page(route="/")
def index():
    return rx.vstack(
        rx.heading("Supabase Google OAuth", size="7"),
        rx.link("Protected Page", href="/protected"),
        align_items="center",
    )


@rx.page(route="/protected")
@require_login
def protected() -> rx.Component:
    return rx.vstack(
        user_info(State.user_data),
        rx.link("Home", href="/"),
        align_items="center",
    )


@rx.page(route="/callback")
def protected() -> rx.Component:
    return rx.vstack(
        rx.text("Loading....."),
        on_mount=State.retrieve_access_token,
        align_items="center",
    )


app = rx.App()
app.add_page(index)