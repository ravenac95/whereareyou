import sys
import click
import netifaces
from github import Github, InputFileContent


@click.command()
@click.option('--gh-token', help='Github token to use')
@click.option('--gh-gist-id', help='Gist id to update')
@click.option('--gh-token-file', help='Github token file')
@click.option('--gh-gist-id-file', help='Gist id file')
def main(gh_token, gh_gist_id, gh_token_file, gh_gist_id_file):
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

    g = Github(gh_token)

    gist = g.get_gist(gh_gist_id)

    gist.edit(files={
        "whereareyou.nuc.txt": InputFileContent(content="\n".join(ips)),
    })


if __name__ == '__main__':
    main()
