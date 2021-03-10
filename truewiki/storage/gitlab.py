import base64
import click
import git
import logging
import tempfile
import os

from openttd_helpers import click_helper

from .git import (
    OutOfProcessStorage as GitOutOfProcessStorage,
    Storage as GitStorage,
)

log = logging.getLogger(__name__)

_gitlab_private_key = None
_gitlab_url = None
_gitlab_history_url = None


class OutOfProcessStorage(GitOutOfProcessStorage):
    def _remove_empty_folders(self, parent_folder):
        removed = False
        for root, folders, files in os.walk(parent_folder, topdown=False):
            if root.startswith(".git"):
                continue

            if not folders and not files:
                os.rmdir(root)
                removed = True

        return removed

    def fetch_latest(self):
        log.info("Updating storage to latest version from GitLab")

        origin = self._git.remotes.origin

        # Checkout the latest master, removing and commits/file changes local
        # might have.
        with self._git.git.custom_environment(GIT_SSH_COMMAND=self._ssh_command):
            try:
                origin.fetch()
            except git.exc.BadName:
                # When the garbage collector kicks in, GitPython gets confused and
                # throws a BadName. The best solution? Just run it again.
                origin.fetch()

        origin.refs.master.checkout(force=True, B="master")
        for file_name in self._git.untracked_files:
            os.unlink(f"{self._folder}/{file_name}")

        # We might end up with empty folders, which the rest of the
        # application doesn't really like. So remove them. Keep repeating the
        # function until no folders are removed anymore.
        while self._remove_empty_folders(self._folder):
            pass

        return True

    def push(self):
        if not self._ssh_command:
            log.error("No GitLab private key supplied; cannot push to GitLab.")
            return True

        try:
            with self._git.git.custom_environment(GIT_SSH_COMMAND=self._ssh_command):
                self._git.remotes.origin.push()
        except Exception:
            log.exception("Git push failed; reloading from GitLab")
            return False

        return True


class Storage(GitStorage):
    out_of_process_class = OutOfProcessStorage

    def __init__(self):
        super().__init__()

        # We need to write the private key to disk: GitPython can only use
        # SSH-keys that are written on disk.
        if _gitlab_private_key:
            self._gitlab_private_key_file = tempfile.NamedTemporaryFile()
            self._gitlab_private_key_file.write(_gitlab_private_key)
            self._gitlab_private_key_file.flush()

            self._ssh_command = f"ssh -i {self._gitlab_private_key_file.name}"

    def prepare(self):
        _git = super().prepare()

        # Make sure the origin is set correctly
        if "origin" not in _git.remotes:
            _git.create_remote("origin", _gitlab_url)
        origin = _git.remotes.origin
        if origin.url != _gitlab_url:
            origin.set_url(_gitlab_url)

        return _git

    def reload(self):
        self._run_out_of_process(self._reload_done, "fetch_latest")

    def _reload_done(self):
        super().reload()

    def commit_done(self):
        self._run_out_of_process(None, "push")

    def get_history_url(self):
        # GitLab history is not paginated
        return f"{_gitlab_history_url}/commits/master/"

    def get_repository_url(self):
        return _gitlab_history_url


@click_helper.extend
@click.option(
    "--storage-gitlab-url",
    help="Repository URL on GitLab.",
    default=None,
    show_default=True,
    metavar="URL",
)
@click.option(
    "--storage-gitlab-history-url",
    help="Repository URL on GitLab to visit history (defaults to --storage-gitlab-url).",
    default=None,
    show_default=True,
    metavar="URL",
)
@click.option(
    "--storage-gitlab-private-key",
    help="Base64-encoded private key to access GitLab." "Always use this via an environment variable!",
)
def click_storage_gitlab(storage_gitlab_url, storage_gitlab_history_url, storage_gitlab_private_key):
    global _gitlab_url, _gitlab_history_url, _gitlab_private_key

    if storage_gitlab_history_url is None:
        storage_gitlab_history_url = storage_gitlab_url

    _gitlab_url = storage_gitlab_url
    _gitlab_history_url = storage_gitlab_history_url
    if storage_gitlab_private_key:
        _gitlab_private_key = base64.b64decode(storage_gitlab_private_key)
