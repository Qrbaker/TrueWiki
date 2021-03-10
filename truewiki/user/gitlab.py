import click
import secrets

from aiohttp import web
from aioauth_client import GitlabClient
from openttd_helpers import click_helper

from .base import User as BaseUser


GITLAB_CLIENT_ID = None
GITLAB_CLIENT_SECRET = None

_gitlab_states = {}


def in_query_gitlab_code(code):
    if code is None:
        raise web.HTTPBadRequest(text="code is not set in query-string")

    # This code is sent by GitLab, and should be at least 20 characters.
    # GitLab makes no promises over the length.
    if len(code) < 20:
        raise web.HTTPBadRequest(text="code seems to be an invalid GitLab callback code")

    return code


def in_query_gitlab_state(state):
    if state is None:
        raise web.HTTPBadRequest(text="state is not set in query-string")

    # We generated this state with token_hex(16), and as such should always
    # be 32 in length.
    if len(state) != 32:
        raise web.HTTPBadRequest(text="state is not a valid uuid")

    return state


@click_helper.extend
@click.option("--user-gitlab-client-id", help="GitLab client ID. (user=gitlab only)")
@click.option(
    "--user-gitlab-client-secret",
    help="GitLab client secret. Always use this via an environment variable! (user=gitlab only)",
)
def click_user_gitlab(user_gitlab_client_id, user_gitlab_client_secret):
    global GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET

    GITLAB_CLIENT_ID = user_gitlab_client_id
    GITLAB_CLIENT_SECRET = user_gitlab_client_secret


class User(BaseUser):
    method = "gitlab"
    routes = web.RouteTableDef()

    def __init__(self, redirect_uri):
        super().__init__(redirect_uri)

        if not GITLAB_CLIENT_ID or not GITLAB_CLIENT_SECRET:
            raise Exception("GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET should be set via environment")

        self._gitlab = GitlabClient(client_id=GITLAB_CLIENT_ID, client_secret=GITLAB_CLIENT_SECRET)

    def get_authorize_page(self):
        # Chance on collision is really low, but would be really annoying. So
        # simply protect against it by looking for an unused UUID.
        state = secrets.token_hex(16)
        while state in _gitlab_states:
            state = secrets.token_hex(16)
        self._state = state

        _gitlab_states[self._state] = self

        # We don't set any scope, as we only want the username + id
        authorize_url = self._gitlab.get_authorize_url(state=self._state)
        return web.HTTPFound(location=authorize_url)

    def get_git_author(self) -> str:
        return (self.display_name, f"{self.display_name.lower()}@users.noreply.gitlab.com")

    @staticmethod
    def get_by_state(state):
        if state not in _gitlab_states:
            return None

        user = _gitlab_states[state]
        user._forget_gitlab_state()

        return user

    def logout(self):
        self._forget_gitlab_state()

        super().logout()

    def _forget_gitlab_state(self):
        if self._state:
            del _gitlab_states[self._state]

        self._state = None

    async def get_user_information(self, code):
        # Validate the code and fetch the user info
        await self._gitlab.get_access_token(code)
        user, _ = await self._gitlab.user_info()

        self.display_name = user.username
        self.id = str(user.id)

    @staticmethod
    @routes.get("/user/gitlab-callback")
    async def login_gitlab_callback(request):
        state = in_query_gitlab_state(request.query.get("state"))
        user = User.get_by_state(state)
        if user is None:
            return web.HTTPNotFound()

        # If "code" is not set, this is most likely a "Cancel" action of the
        # user on the GitLab Authorize page. So do the only thing we can do ..
        # redirect the user to the redirect-uri, and let him continue his
        # journey.
        if "code" not in request.query:
            return web.HTTPFound(location=f"{user.redirect_uri}")

        code = in_query_gitlab_code(request.query.get("code"))
        await user.get_user_information(code)
        return user.validate()

    @staticmethod
    def get_description():
        return "Login via GitLab"

    @staticmethod
    def get_settings_url():
        return f"https://gitlab.com/-/profile/applications/{GITLAB_CLIENT_ID}"
