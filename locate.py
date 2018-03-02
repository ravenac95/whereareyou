"""
A simple script to locate a specific server on your local network. So
your lazy self doesn't need to connect to it manually.
"""
import os
import sys
import json
import click
import base64
import netifaces
import getpass
from github import Github, InputFileContent
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt(plaintext, public_key):
    key = Fernet.generate_key()

    # Wrap the key in the public
    wrapped_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    f = Fernet(key)
    token = f.encrypt(str.encode(plaintext))

    return json.dumps({
        "token": token.decode(),
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
    })


def decrypt(raw_payload, private_key):
    payload = json.loads(raw_payload)

    unwrapped_key = private_key.decrypt(
        base64.b64decode(payload['wrapped_key']),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    f = Fernet(unwrapped_key.decode())

    plaintext_bytes = f.decrypt(str.encode(payload['token']))
    return plaintext_bytes.decode()


def matches_cache(cache_file, ips_str):
    if not os.path.exists(cache_file):
        return False

    if open(cache_file).read() == ips_str:
        return True
    return False


@click.group()
def cli():
    pass


@cli.command()
@click.option('--gh-token', help='Github token to use')
@click.option('--gh-gist-id', help='Gist id to update')
@click.option('--gh-token-file', help='Github token file')
@click.option('--gh-gist-id-file', help='Gist id file')
@click.option('--gh-gist-file-name', help='Gist file name to update')
@click.option('--public-key-path', default=os.path.expanduser('~/.ssh/id_rsa.pub'), type=click.Path(exists=True), help='Public key to encrypt the message')
@click.option('--cache-file', default='.localcache', help='The cache file')
def announce(gh_token, gh_gist_id, gh_token_file, gh_gist_id_file, gh_gist_file_name, public_key_path, cache_file):
    if not gh_token:
        if not gh_token_file:
            print("Need a github token to continue")
            sys.exit(1)
        else:
            gh_token = open(gh_token_file).read().strip()

    if not gh_gist_id:
        if not gh_gist_id_file:
            print("Need a github gist id to continue")
            sys.exit(1)
        else:
            gh_gist_id = open(gh_gist_id_file).read().strip()

    ips = []

    interfaces = netifaces.interfaces()

    for interface in interfaces:
        ifaddresses = netifaces.ifaddresses(interface)

        ipv4_setup = ifaddresses.get(netifaces.AF_INET, [])
        for ipv4 in ipv4_setup:
            ip = ipv4.get('addr', None)
            if not ip:
                continue
            ips.append(ip)

    # Sort ips so we can compare the cache
    ips.sort()

    ips_str = "\n".join(ips)

    # Compare the cache
    if matches_cache(cache_file, ips_str):
        print("Nothing has changed since the last update. Do nothing.")
        sys.exit(0)

    g = Github(gh_token)

    gist = g.get_gist(gh_gist_id)

    public_key = serialization.load_ssh_public_key(
        str.encode(open(public_key_path).read()),
        backend=default_backend(),
    )

    file_content = encrypt(ips_str, public_key)

    gist.edit(files={
        gh_gist_file_name: InputFileContent(content=file_content),
    })

    # Save cache
    cache = open(cache_file, 'w')
    cache.write(ips_str)
    cache.close()


@cli.command()
@click.option('--gh-token', help='Github token to use')
@click.option('--gh-gist-id', help='Gist id to update')
@click.option('--gh-token-file', help='Github tokn file')
@click.option('--gh-gist-id-file', help='Gist id file')
@click.option('--gh-gist-file-name', help='Gist file name to update')
@click.option('--private-key-path', default=os.path.expanduser('~/.ssh/id_rsa'), type=click.Path(exists=True), help='Public key to encrypt the message')
def locate(gh_token, gh_gist_id, gh_token_file, gh_gist_id_file, gh_gist_file_name, private_key_path):
    g = Github(gh_token)

    gist = g.get_gist(gh_gist_id)

    gist_file = gist.files[gh_gist_file_name]

    private_key_password = str.encode(
        getpass.getpass("Private key passphrase:"))

    private_key = serialization.load_pem_private_key(
        str.encode(open(private_key_path).read()),
        password=private_key_password,
        backend=default_backend(),
    )

    print(decrypt(gist_file.content, private_key))


if __name__ == '__main__':
    cli()
