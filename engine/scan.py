#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import re
import json
import os

from tornado import ioloop, httpclient
from engine.core import *
from engine.wordpress import *
from lxml import etree
from multiprocessing import Process, Pool


class Scan_Engine:
    def __init__(self, wordpress, aggressive, api_token):
        self.fingerprint_wp_version(wordpress)
        self.list_wp_version_vulnerabilities(wordpress, "wordpresses", api_token)
        if not aggressive:
            self.enumerating_themes_passive(wordpress, api_token)
            self.enumerating_plugins_passive(wordpress, api_token)
        else:
            self.enumerating_themes_aggressive(wordpress)
            self.enumerating_plugins_aggressive(wordpress)
        self.api_token = ""  # Flushes the value of api_token

    """
    name        : fingerprint_wp_version_meta_based(wordpress)
    description : detect the version of WordPress based on the meta tag
    """

    def fingerprint_wp_version_meta_based(self, wordpress):
        regex = re.compile('meta name="generator" content="WordPress (.*?)"')
        match = regex.findall(wordpress.index.text)
        if match:
            wordpress.version = match[0]
            print(critical("WordPress version %s identified from advanced fingerprinting" % wordpress.version))
            return True
        return False

    """
    name        : fingerprint_wp_version_feed_based(wordpress)
    description : detect the version of WordPress based on the generator tag in index.php/feed/
    """

    def fingerprint_wp_version_feed_based(self, wordpress):
        r = requests.get(wordpress.url + "index.php/feed", headers={"User-Agent": wordpress.agent}, verify=False).text
        regex = re.compile('generator>https://wordpress.org/\?v=(.*?)<\/generator')
        match = regex.findall(r)
        if match:
            wordpress.version = match[0]
            print(critical("WordPress version %s identified from advanced fingerprinting" % wordpress.version))
            return True
        return False

    """
    name        : fingerprint_wp_version_hash_based(wordpress)
    description : compare hashes of unique files in order to detect the version
    """

    def fingerprint_wp_version_hash_based(self, wordpress):
        tree = etree.parse("database/wp_versions.xml")
        root = tree.getroot()

        # Iterating through 'src' file
        for i in range(len(root)):

            # Download file
            ddl_url = (wordpress.url + root[i].get('src')).replace('$', '')
            ddl_name = "/tmp/" + (root[i].get('src').replace('/', '-'))
            download_file(ddl_url, ddl_name, True)

            # Get hash of the file
            ddl_hash = md5_hash(ddl_name)

            # Delete the file
            remove_file(ddl_name)

            # Iterating throug 'md5' hash
            for j in range(len(root[i])):
                if "Element" in str(root[i][j]):

                    # Detect the version
                    if ddl_hash == root[i][j].get('md5'):
                        wordpress.version = root[i][j][0].text
                        print(critical(
                            "WordPress version %s identified from advanced fingerprinting" % wordpress.version))
                        return

    """
    name        : fingerprint_wp_version(wordpress)
    description : launch different methods to get the wordpress version
    """

    def fingerprint_wp_version(self, wordpress):
        # Meta tag based
        if not self.fingerprint_wp_version_meta_based(wordpress):
            # Feed based <generator>
            if not self.fingerprint_wp_version_feed_based(wordpress):
                # Hash based
                self.fingerprint_wp_version_hash_based(wordpress)

    """
    name        : list_wp_version_vulnerabilities(self, wordpress, file)
    description : display info about vulnerabilities affecting the current wordpress
    """

    def list_wp_version_vulnerabilities(self, wordpress, file, api_token):
        # Try to get a close result if the version is not in the list
        check_wordpress_data(wordpress.version, api_token)

    """
    name        : enumerating_themes_passive(self, wordpress)
    description : enumerate every theme used by the wordpress
    """

    def enumerating_themes_passive(self, wordpress, api_token):
        print(notice("Enumerating themes from passive detection ..."))

        # Theme name (css file)
        regex = re.compile('wp-content/themes/(.*?)/.*?[css|js].*?ver=([0-9\.]*)')
        match = regex.findall(wordpress.index.text)
        theme = {}

        # Unique theme
        for m in match:

            # Remove minified and github version
            theme_name = m[0]
            theme_name = theme_name.replace('-master', '')
            theme_name = theme_name.replace('.min', '')
            theme_version = m[1]

            if m[0] not in theme.keys():
                theme[m[0]] = m[1]

                print(warning("Name: %s - v%s" % (theme_name, theme_version)))
                update_component_data(theme_name, "themes", api_token)
                print_components(theme_name, theme_version, "themes")

        wordpress.themes = theme

    """
    name        : enumerating_plugins_passive(self, wordpress)
    description : enumerate every plugins used by the wordpress
    """

    def enumerating_plugins_passive(self, wordpress, api_token):
        print(notice("Enumerating plugins from passive detection ..."))

        # Plugin name (js file)
        regex = re.compile('wp-content/plugins/(.*?)/.*?[css|js].*?ver=([0-9\.]*)')
        match = regex.findall(wordpress.index.text)
        plugin = {}

        # Unique plugin
        for m in match:

            # Remove minified and github version
            plugin_name = m[0]
            plugin_name = plugin_name.replace('-master', '')
            plugin_name = plugin_name.replace('.min', '')
            plugin_version = m[1]

            if plugin_name not in plugin.keys() and m[1] != '1':
                plugin[plugin_name] = m[1]

                print(warning("Name: %s - v%s" % (plugin_name, plugin_version)))
                update_component_data(plugin_name, "plugins", api_token)
                print_components(plugin_name, plugin_version, "plugins")

        wordpress.plugins = plugin

    """
    name        : enumerating_themes_aggressive(self, wordpress)
    description : enumerate every themes used by the wordpress
    """

    def enumerating_themes_aggressive(self, wordpress):
        print(notice("Enumerating themes from aggressive detection ..."))

        # Load json file
        with open('database/themes.json') as data_file:
            data = json.load(data_file)

            # Run through every themes
            global iter_aggressive
            iter_aggressive = 0
            http_client = httpclient.AsyncHTTPClient()
            for plugin in data.keys():
                iter_aggressive += 1
                http_client.fetch(wordpress.url + '/wp-content/themes/' + plugin, aggressive_request_themes,
                                  method='HEAD', validate_cert=False) == True
            ioloop.IOLoop.instance().start()

    """
    name        : enumerating_plugins_aggressive(self, wordpress)
    description : enumerate every plugins used by the wordpress
    """

    def enumerating_plugins_aggressive(self, wordpress):
        print(notice("Enumerating plugins from aggressive detection ..."))

        # Load json file
        with open('database/plugins.json') as data_file:
            data = json.load(data_file)

            # Run through every plugin
            global iter_aggressive
            iter_aggressive = 0
            http_client = httpclient.AsyncHTTPClient()
            for plugin in data.keys():
                iter_aggressive += 1
                http_client.fetch(wordpress.url + '/wp-content/plugins/' + plugin, aggressive_request_plugins,
                                  method='HEAD', validate_cert=False) == True
            ioloop.IOLoop.instance().start()


def aggressive_request_plugins(response):
    if response.code == 200:
        print_components(response.effective_url.split('/')[-2], None, "plugins")

    global iter_aggressive
    iter_aggressive -= 1
    if iter_aggressive == 0:
        ioloop.IOLoop.instance().stop()


def aggressive_request_themes(response):
    if response.code == 200:
        print_components(response.effective_url.split('/')[-2], None, "themes")

    global iter_aggressive
    iter_aggressive -= 1
    if iter_aggressive == 0:
        ioloop.IOLoop.instance().stop()
