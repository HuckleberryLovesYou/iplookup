#!/usr/bin/python3

###########################################################################################################
#        This code is inspired by ebola man                                                               #
#        https://www.youtube.com/@ebolaman_                                                               #
#        The idea came from this video:                                                                   #
#        https://www.youtube.com/watch?v=oQxAVIZdktU                                                      #
#        He made a similar program like this                                                              #
#        in C# and I thought I should                                                                     #
#        rewrite it in Python.                                                                            #
###########################################################################################################


import requests
import json
import argparse
from sys import argv



def request_ipinfo_api(requested_ip) -> int:
    ipinfo_api_requested_url = f"https://ipinfo.io/{requested_ip}/json"
    ipinfo_api_call = requests.get(ipinfo_api_requested_url)
    ipinfo_api_response_statuscode = ipinfo_api_call.status_code
    ipinfo_api_response_json = json.loads(ipinfo_api_call.text)
    ipinfo_api_response_coord_latitude, ipinfo_api_response_coord_longitude = f"{ipinfo_api_response_json["loc"]}".split(',')
    google_maps_link = f"https://www.google.com/maps/search/?api=1&query={ipinfo_api_response_coord_latitude},{ipinfo_api_response_coord_longitude}"
    print("\n")
    print(f"The IP '{requested_ip}' is located in {ipinfo_api_response_json["postal"]} {ipinfo_api_response_json["city"]} in {ipinfo_api_response_json["region"]}, {ipinfo_api_response_json["country"]}")
    print(f"The coordinates are: {ipinfo_api_response_json["loc"]}")
    print(f"Google Maps URI\n{google_maps_link}")
    print("\n")
    return ipinfo_api_response_statuscode

def is_valid_ip(ip: str) -> bool:
    if ip == "":
        return False
    if not ip.count(".") == 3:
        return False
    octets = ip.split(".")
    for octet in octets:
        if octet.isdigit():
            octet = int(octet)
        else:
            return False

        if (octet < 0) or (octet > 255):
            return False

    return True

def get_args() -> argparse:
    parser = argparse.ArgumentParser(description="IPv4 Lookup shortcuts\nCommand example: python iplookup.py --ip 123.123.123.123")
    parser.add_argument("-o", "--own-ip", action="store_true", dest="own_ip", help="This will get your current IP look it up and show it.")
    parser.add_argument("-ip", "--ip", action="store", dest="ip", type=str, help="Enter valid IP to look up.")
    return parser.parse_args()

def get_own_ip() -> str:
    api_uri = "https://checkip.amazonaws.com/"
    api_call = requests.get(api_uri)
    return api_call.text[:-1]

def main():
    args_passed: bool = False
    # Check if any arguments were passed, excluding the program name
    if len(argv) > 1:
        try:
            args = get_args()
            args_passed: bool = True
        except SystemExit: # This exception is raised when -h or --help is called and help is printed
            quit("Exiting. User entered '-h/--help'")
        except Exception as e:
            print(f"E: Error parsing arguments: {e}\nUsing interactive mode instead")
    else:
        print("No arguments provided. Using interactive mode.")


    if args_passed:
        if args.own_ip:
            requested_ip = get_own_ip()
        else:
            requested_ip = args.ip
    else:
        requested_ip: str = input("Enter IP: ")

    if not is_valid_ip(requested_ip):
        print("Please enter an valid IP (e.g. 140.82.121.4; no IPv6)")
    else:
        api_statuscode: int = request_ipinfo_api(requested_ip)
        if not api_statuscode == 200:
            print(f"API call failed\nYour API call returned {api_statuscode} status code.")


if __name__ == "__main__":
    main()