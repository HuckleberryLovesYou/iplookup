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
from string import hexdigits


def request_ipinfo_api(requested_ip: str) -> int:
    if requested_ip == "self":
        ipinfo_api_requested_url = f"https://ipinfo.io/json"
    else:
        ipinfo_api_requested_url = f"https://ipinfo.io/{requested_ip}/json"
    ipinfo_api_call = requests.get(ipinfo_api_requested_url)
    ipinfo_api_response_statuscode = ipinfo_api_call.status_code
    ipinfo_api_response_json = json.loads(ipinfo_api_call.text)
    ipinfo_api_response_coord_latitude, ipinfo_api_response_coord_longitude = f"{ipinfo_api_response_json["loc"]}".split(',')
    google_maps_link = f"https://www.google.com/maps/search/?api=1&query={ipinfo_api_response_coord_latitude},{ipinfo_api_response_coord_longitude}"
    print("\n")
    print(f"The IP '{requested_ip}' is located in '{ipinfo_api_response_json["postal"]} {ipinfo_api_response_json["city"]}' in '{ipinfo_api_response_json["region"]}, {ipinfo_api_response_json["country"]}'")
    print(f"The coordinates are: {ipinfo_api_response_json["loc"]}")
    print(f"Google Maps URI\n{google_maps_link}")
    print("\n")
    return ipinfo_api_response_statuscode

def is_valid_ipv4(ip: str) -> bool:
    if ip == "":
        print("Didn't pass an IP Address.")
        return False
    if not ip.count(".") == 3:
        print("Ensure IP Address is following the Dotted decimal notation (Dot-decimal notation) (e.g. 140.82.121.4)")
        return False
    octets = ip.split(".")
    for i, octet in enumerate(octets):
        if octet.isdigit():
            octet = int(octet)
        else:
            print(f"No digits ({octet}) in octet {i + 1}")
            return False

        if (octet < 0) or (octet > 255):
            print(f"Number ({octet}) out of valid range in octet {i + 1}")
            return False

    return True

def expand_ipv6(ip: str) -> str:
    hextets = ip.split(":")
    missing_hextets = 8 - len(hextets) + 1

    find_index = ip.find("::") + 1

    # gets the index in hextets where the '::' was found
    counter = 0
    for i, hextet in enumerate(hextets):
        counter += len(hextet) + 1
        if counter == find_index:
            double_column_index = i + 1
    hextets.pop(double_column_index)

    # expand IPv6 Address
    for i in range(missing_hextets):
        hextets.insert(double_column_index, "0000")
    if hextets[-1] == "":
        hextets.pop()
        hextets.append("0000")

    # expand every hextet in hextets
    for i, hextet in enumerate(hextets):
        missing_characters = 4 - len(hextet)
        if missing_characters > 0:
            new_str = f"{"0" * missing_characters}{hextet}"
            hextets.pop(i)
            hextets.insert(i, new_str)
    ip: str = ""
    for i, hextet in enumerate(hextets):
        ip += hextet
        if not i == (len(hextets) - 1):
            ip += ":"
    return ip

def is_valid_ipv6(ip: str) -> bool:
    if not isinstance(ip, str):
        print(f"Type of 'ip' is expected to be a str, not {type(ip)}")
    if ip == "":
        print("Didn't pass an IPv6 Address.")
        return False
    if not ip.count(":") == 7:
        print("Detected shortened IPv6 Address.")
        if ip.count("::") != 1:
            print("Shortened IPv6 Addresses only allow the occurrence of '::' once.")
            return False
        expanded_ip = expand_ipv6(ip).split(":")
    else:
        expanded_ip = ip.split(":")

    for hextet_nr, hextet in enumerate(expanded_ip):
        for character_nr, character in enumerate(hextet):
            if character not in hexdigits:
                print(f"No hexdigit ({character}) in hextet {hextet_nr + 1} at character {character_nr + 1}")
                return False
    return True


def get_args() -> argparse:
    parser = argparse.ArgumentParser(description="IPv4 Lookup shortcuts\nCommand example: python iplookup.py --ip 123.123.123.123")
    parser.add_argument("-o", "--own-ip", action="store_true", dest="own_ip", help="This will get your current IP look it up and show it.")
    parser.add_argument("-ipv4", "--ipv4", action="store", dest="ipv4", type=str, help="Enter valid IPv4-Address to look up.")
    parser.add_argument("-ipv6", "--ipv6", action="store", dest="ipv6", type=str, help="Enter valid IPv6-Address to look up.")
    return parser.parse_args()

def main():
    args_passed: bool = False
    # Check if any arguments were passed, excluding the program name
    if len(argv) > 1:
        try:
            args = get_args()
            args_passed: bool = True
        except SystemExit:  # This exception is raised when -h or --help is called and help is printed
            quit("Exiting. User entered '-h/--help'")
        except Exception as e:
            print(f"Error parsing arguments: {e}\nUsing interactive mode instead.")
    else:
        print("No arguments provided. Using interactive mode.")

    if args_passed:
        if args.own_ip:
            request_ipinfo_api(4, "self")
            quit()
        else:
            if args.ipv4 is None and args.ipv6 is None:
                quit("No IPv4 or IPv6 Address specified. Pass one IP Address for one IP Version.")
            if args.ipv4 is not None and args.ipv6 is not None:
                quit("IPv4 and IPv6 Address specified. Only use one IP Version at a time.")

            if args.ipv4 is not None:
                if is_valid_ipv4(args.ipv4):
                    api_statuscode: int = request_ipinfo_api(args.ipv4)
                    if not api_statuscode == 200:
                        print(f"API call failed\nYour API call returned {api_statuscode} status code. Check your WAN-Connection.")
            else:
                if is_valid_ipv6(args.ipv6):
                    api_statuscode: int = request_ipinfo_api(expand_ipv6(args.ipv6))
                    if not api_statuscode == 200:
                        print(f"API call failed\nYour API call returned {api_statuscode} status code. Check your WAN-Connection.")
    else:
        requested_ip: str = input("Enter IP: ")
        if requested_ip.count(".") > 0:
            if is_valid_ipv4(requested_ip):
                api_statuscode: int = request_ipinfo_api(requested_ip)
                if not api_statuscode == 200:
                    print(f"API call failed\nYour API call returned {api_statuscode} status code. Check your WAN-Connection.")
        else:
            if is_valid_ipv6(requested_ip):
                api_statuscode: int = request_ipinfo_api(expand_ipv6(requested_ip))
                if not api_statuscode == 200:
                    print(f"API call failed\nYour API call returned {api_statuscode} status code. Check your WAN-Connection.")


if __name__ == "__main__":
    main()