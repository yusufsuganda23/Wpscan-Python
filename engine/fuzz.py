import requests
from concurrent.futures import ThreadPoolExecutor
from engine.core import *
from engine.wordpress import *
from lxml import etree

class Fuzz_Engine:
    def __init__(self, wordpress, fuzz):
        if fuzz:
            self.fuzzing_component_aggressive(wordpress)
            self.fuzzing_themes_aggressive(wordpress)
            self.fuzzing_plugins_aggressive(wordpress)

    def fuzzing_component_aggressive(self, wordpress):
        print(notice("Enumerating components from aggressive fuzzing ..."))

        with open('fuzz/wordpress.fuzz') as data_file:
            with ThreadPoolExecutor() as executor:
                for component in data_file:
                    component = component.strip()
                    executor.submit(self.aggressive_request_component, wordpress.url + component)

    def fuzzing_themes_aggressive(self, wordpress):
        print(notice("Enumerating themes from aggressive fuzzing ..."))

        with open('fuzz/wp_themes.fuzz') as data_file:
            with ThreadPoolExecutor() as executor:
                for theme in data_file:
                    theme = theme.strip()
                    executor.submit(self.aggressive_request_themes, wordpress.url + theme + "style.css")

    def fuzzing_plugins_aggressive(self, wordpress):
        print(notice("Enumerating plugins from aggressive fuzzing ..."))

        with open('fuzz/wp_plugins.fuzz') as data_file:
            with ThreadPoolExecutor() as executor:
                for plugin in data_file:
                    plugin = plugin.strip()
                    executor.submit(self.aggressive_request_plugins, wordpress.url + plugin)

    def aggressive_request_plugins(self, url):
        response = requests.head(url, verify=False)
        if response.status_code == 200:
            print(warning(response.url.split('/')[-2]))

    def aggressive_request_themes(self, url):
        response = requests.head(url, verify=False)
        if response.status_code == 200:
            print(warning(response.url.split('/')[-2]))

    def aggressive_request_component(self, url):
        response = requests.head(url, verify=False)
        if response.status_code == 200:
            if "reauth" in response.url:
                print("[i] Authentication Needed: " + response.url + " - found")
            else:
                print("[i] File: " + response.url + " - found")
