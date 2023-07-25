#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import os
import time
import hashlib
import json

"""
name        : notice(msg), critical(msg), warning(msg), info(msg)
description : add color to message based on their impact
return      : string
"""


def ask(msg):
    return "\033[1m[?] " + msg + "\033[0m"


def notice(msg):
    return "\n\033[1m[i] " + msg + "\033[0m"


def critical(msg):
    return "\033[91m[!] " + msg + "\033[0m"


def warning(msg):
    return "\033[93m[i] " + msg + "\033[0m"


def info(msg):
    return "\033[0m[+] " + msg + "\033[0m"


def vulnerable(msg):
    return "\033[91m[!]" + msg + "\033[0m"


def display(msg):
    return "\033[0m | " + msg + "\033[0m"


"""
name        : format_url()
description : will format the URL to provide an http
"""


def format_url(url):
    if not "http" in url:
        return "http://" + url
    return url


"""
name        : download_file(url, filename)
description : will download a file from url into filename
"""


def download_file(url, filename, verbosity):
    try:

        # Open the request
        source = requests.get(url).text

        # Write the file
        with open(filename, 'wb') as ddl_file:
            ddl_file.write(source.encode('utf8'))

    except Exception as e:
        raise e


"""
name        : remove_file(filename)
description : will remove a file from the computer
"""


def remove_file(filename):
    try:
        os.remove(filename)
    except Exception as e:
        raise e


"""
name        : md5_hash(filename)
description : will compute the md5 hash of the file
return      : string
"""


def md5_hash(filename):
    return hashlib.md5(open(filename, 'rb').read()).hexdigest()


"""
name        : is_lower(str_one, str_two)
description : will compare two string version
return      : boolean
"""


def is_lower(str_one, str_two, equal):
    sum_one = 0
    sum_two = 0

    # Handle the NoneType
    if str_one is None:
        if str_two is None:
            return False
        else:
            return True

    if str_two is None:
        if str_one is None:
            return False
        else:
            return True

    # Fix for X.X <= X.X.X and X.X.X <= X.X
    if len(str_one) < 5:
        str_one += '.0'
    if len(str_two) < 5:
        str_two += '.0'

    str_one = str_one[::-1].split('.')
    str_two = str_two[::-1].split('.')

    for i in range(len(str_one)):
        try:
            sum_one += ((i + 1) ** 10) * (int(str_one[i]))
            sum_two += ((i + 1) ** 10) * (int(str_two[i]))
        except Exception as e:
            return True

    # For inferior
    if sum_one < sum_two:
        return True

    # Handle < and = if define in equal
    if equal and sum_one == sum_two:
        return True

    return False


"""
name        : print_components(name, version, file):
description : display info about vulnerability from the file
"""


def print_components(name, version, file):
    # Load json file
    with open('database/' + file + '.json') as data_file:
        data = json.load(data_file)

    plugin_info = data.get(name)
    if plugin_info:
        plugin_data = plugin_info[name]
        latest_version = plugin_data['latest_version']
        vulnerabilities = plugin_data['vulnerabilities']

        print(warning("Name: %s" % name))

        if version is not None:
            if is_lower(version, latest_version, False):
                print(info("The version is out of date, the latest version is %s" % latest_version))
            else:
                print(info("The version is up to date, the latest version is %s" % latest_version))

        if vulnerabilities:
            for vuln in vulnerabilities:
                vuln_type = vuln['vuln_type']
                title = vuln['title']
                vuln_id = vuln['id']
                fixed_in = vuln.get('fixed_in')

                print("\t", vulnerable("%s: %s - ID:%s" % (vuln_type, title, vuln_id)))
                print("\t", display("Fixed in %s" % fixed_in)) if fixed_in else None

                references = vuln['references']
                if references:
                    print("\t", display("References:"))
                    for ref_key, ref_list in references.items():
                        for ref in ref_list:
                            if ref_key == 'url':
                                print("\t\t - %s" % ref)
                            else:
                                print("\t\t - %s %s" % (ref_key.capitalize(), ref))
        else:
            print(info("No vulnerability information available for this component."))
    else:
        print(info("Component not found in the database."))


def update_component_data(component_name, component_type, api_token):
    file_location = f"database/{component_type}.json"

    # Check if the JSON file exists
    if os.path.exists(file_location):
        with open(file_location, 'r') as f:
            file_data = f.read()

        # Check if the file is empty or contains invalid JSON
        if file_data.strip():
            existing_data = json.loads(file_data)
        else:
            existing_data = {}
    else:
        existing_data = {}

    # Check if the component_name already exists in the dictionary
    if component_name in existing_data:
        print(f"{component_type.capitalize()} '{component_name}' already exists in the JSON dictionary.")
        return

    url = f'https://wpscan.com/api/v3/{component_type}/{component_name}'
    headers = {
        'accept': 'application/json',
        'Authorization': f'Token token={api_token}'
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            new_data = response.json()

            # Add the new data to the dictionary
            existing_data[component_name] = new_data

            with open(file_location, 'w') as f:
                json.dump(existing_data, f)

            print("Request successful. Data appended to the JSON file.")
        elif response.status_code == 429:
            print("API rate limit exceeded. Please change your API or try again tomorrow!.")
        else:
            print("Request failed. Status code:", response.status_code)

    except requests.RequestException as e:
        print("Request failed. Exception:", str(e))

    except json.JSONDecodeError as e:
        print("JSON decoding failed. Exception:", str(e))


def check_wordpress_data(wordpress_version, api_token):
    file_location = "database/wordpresses.json"

    # Check if the JSON file exists
    if os.path.exists(file_location):
        with open(file_location, 'r') as f:
            existing_data = json.load(f)
    else:
        existing_data = {}

    # Check if the WordPress version already exists in the dictionary
    if wordpress_version in existing_data:
        print(f"WordPress version '{wordpress_version}' already exists in the JSON dictionary.")
        print_wordpress_data(existing_data, wordpress_version)  # Call the print_wordpress_data function here
        return

    wordpress_check = wordpress_version.replace(".", "")

    url = f'https://wpscan.com/api/v3/wordpresses/{wordpress_check}'
    headers = {
        'accept': 'application/json',
        'Authorization': f'Token token={api_token}'
    }

    try:
        response = requests.get(url, headers=headers)

        if response.ok:
            new_data = response.json()
            existing_data[wordpress_version] = new_data[wordpress_version]

            with open(file_location, 'w') as f:
                json.dump(existing_data, f)

            print("Request successful. Data appended to the JSON file.")

            # Print the WordPress data
            print_wordpress_data(existing_data, wordpress_version)  # Call the print_wordpress_data function here

        else:
            print("Request failed. Status code:", response.status_code)

    except requests.RequestException as e:
        print("Request failed. Exception:", str(e))


def print_wordpress_data(data, wordpress_version):
    # This version doesn't exist
    if wordpress_version not in data:
        print(warning("The version %s isn't in the database" % wordpress_version))
        return

    version = wordpress_version
    if data[wordpress_version]["vulnerabilities"] == []:
        versions = data.keys()
        for v in versions:
            if v[:4] in wordpress_version and is_lower(wordpress_version, v, False):
                version = v
                break

    # Best accurate result
    for vuln in data[version]["vulnerabilities"]:
        # Basic infos
        print(warning("\t%s : %s - ID:%s" % (vuln['vuln_type'], vuln['title'], vuln['id'])))
        print(info("\tFixed in %s" % vuln['fixed_in']))

        # Display references
        print(info("\tReferences:"))
        for ref_key, ref_value in vuln['references'].items():
            if ref_key == 'url':
                print(info("\tURLs:"))
                for url in ref_value:
                    print(info(f"\t- {url}"))
            else:
                print(info(f"\t{ref_key.capitalize()}:"))
                for ref in ref_value:
                    print(info(f"\t- {ref}"))

        print()
