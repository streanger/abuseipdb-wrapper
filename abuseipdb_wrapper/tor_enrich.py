"""collect informations about tor exit nodes"""
import ipaddress
import requests


def get_tor_exit_nodes():
    """list of ourly checked tor exit nodes from github Tor-IP-Addresses
    https://github.com/SecOps-Institute/Tor-IP-Addresses
    """
    url = "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"
    response = requests.get(url)
    ips = [str(ipaddress.ip_address(item)) for item in response.text.splitlines()]
    return set(ips)


def get_tor_nodes():
    """list of ourly checked tor nodes from github Tor-IP-Addresses
    https://github.com/SecOps-Institute/Tor-IP-Addresses
    """
    url = "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-nodes.lst"
    response = requests.get(url)
    ips = [str(ipaddress.ip_address(item)) for item in response.text.splitlines()]
    return set(ips)


if __name__ == "__main__":
    tor_nodes = get_tor_nodes()
    tor_exit_nodes = get_tor_exit_nodes()
