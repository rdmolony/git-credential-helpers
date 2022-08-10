#!/usr/bin/env python3
"""
git-credential helper for accessing private GitHub repositories

[GitHub Apps](https://docs.github.com/en/free-pro-team@latest/developers/apps)
can provide fine grained, per-repository access control. This helper lets
git automatically create GitHub app installation tokens for interacting
with private repos that have the GitHub app installed.
"""
import argparse
from datetime import datetime
from datetime import timedelta
import re
import sys
import typing

from cryptography.hazmat.primitives import serialization
import github3
import jwt
import requests


def generate_jwt(private_key_pem: str, app_id: int) -> str:

    with open(private_key_pem, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None,
        )

    one_minute_ago = datetime.now() - timedelta(seconds=60)
    in_10_minutes = datetime.now() + timedelta(seconds=600)
    payload = {
        # issued at time, 60 seconds in the past to allow for clock drift
        "iat": one_minute_ago,
        # JWT expiration time (10 minute maximum)
        "exp": in_10_minutes,
        # GitHub App's identifier
        "iss": app_id
    }

    return jwt.encode(payload, key, algorithm="RS256")


def get_installation_id(owner: str, repo: str, headers: typing.Dict[str, str]) -> int:
    return requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/installation", headers=headers
    ).json().get("id")


def generate_installation_token(
    installation_id: int, headers: typing.Dict[str, str]
) -> int:
    return requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=headers,
    ).json().get("token")


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '--app-key-file',
        help='Path to RSA private key file of the GitHub app',
        required=True,
        type=argparse.FileType('r')
    )
    argparser.add_argument(
        '--app-id',
        help='GitHub app id',
        type=int,
        required=True
    )
    argparser.add_argument(
        'operation',
        # We don't want to print to stderr when 'store' or 'erase'
        # are passed to the script. So we accept all possibilities,
        # but only respond to 'get'
        choices=['get', 'store', 'erase'],
        help='git credential operation to perform. Only get is supported',
    )

    args = argparser.parse_args()

    if args.operation != 'get':
        # This isn't a persistent credential helper, so we don't support store or erase
        sys.exit(1)

    # Parse '=' delimited input via stdin
    # Documented at https://git-scm.com/docs/git-credential#IOFMT
    keys = {}
    for l in sys.stdin:
        parts = l.strip().split('=', 1)
        keys[parts[0]] = parts[1]


    # Password for cloning a repo is based on the organization / user that
    # has installed the GitHub app.
    owner, repo = keys['path'].split('/', 1)

    # git clone URL might have a '.git' in it. The GitHub apps API doesn't
    # recognize it as part of the repo name. Since we're making API requests,
    # we should strip this too.
    repo = re.sub(r'\.git$', '', repo)

    print(f'Generating JWT...')
    generated_jwt = generate_jwt(private_key_pem=args.app_key_file, app_id=args.app_id)
    print(generated_jwt)

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {generated_jwt}"
    }

    print(f'Generating installation token...')
    installation_id = get_installation_id(owner=owner, repo=repo, headers=headers)
    installation_token = generate_installation_token(
        installation_id=installation_id, headers=headers
    )
    print(installation_token)

    print(f'username=x-access-token')
    print(f'password={installation_token}')

    print(f'Logging in...')
    gh = github3.github.GitHub()
    gh.login(username="x-access-token", password=installation_token)


if __name__ == '__main__':
    main()
