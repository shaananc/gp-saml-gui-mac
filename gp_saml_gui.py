#!/usr/bin/env python3

import warnings
import sys

from PyQt5 import QtWidgets, QtWebEngineWidgets, QtCore


import argparse
import urllib3
import requests
import xml.etree.ElementTree as ET
import ssl
import tempfile

from operator import setitem
from os import path, dup2, execvp, environ
from shlex import quote
from sys import stderr, platform
from binascii import a2b_base64, b2a_base64
from urllib.parse import urlparse, urlencode, urlunsplit
from html.parser import HTMLParser


class CommentHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.comments = []

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


COOKIE_FIELDS = ("prelogin-cookie", "portal-userauthcookie")


class SAMLLoginView:
    def __init__(self, uri, html, args):

        self.app = QtWidgets.QApplication([])
        self.window = QtWidgets.QMainWindow()

        self.closed = False
        self.success = False
        self.saml_result = {}
        self.verbose = args.verbose

        self.wview = QtWebEngineWidgets.QWebEngineView()

        if args.user_agent is None:
            args.user_agent = "PAN GlobalProtect"
        self.wview.page().profile().setHttpUserAgent(args.user_agent)

        self.window.resize(500, 500)
        self.window.setCentralWidget(self.wview)
        self.window.setWindowTitle("SAML Login")
        self.window.show()

        if html:
            self.wview.setHtml(html, QtCore.QUrl(uri))
        else:
            self.wview.setUrl(QtCore.QUrl(uri))

        self.wview.loadFinished.connect(self.on_load_changed)

    def on_load_changed(self, success):
        if not success:
            print("[ERROR] Failed to load page.", file=stderr)
            return

        # Extract URL and HTML content
        page = self.wview.page()
        page.toHtml(self.handle_html)

    def handle_html(self, html):
        # Here you would parse the HTML to extract SAML responses.
        html_parser = CommentHtmlParser()
        html_parser.feed(html)

        fd = {}
        for comment in html_parser.comments:
            try:
                xmlroot = ET.fromstring("<fakexmlroot>%s</fakexmlroot>" % comment)
                for elem in xmlroot:
                    if elem.tag.startswith("saml-") or elem.tag in COOKIE_FIELDS:
                        fd[elem.tag] = elem.text
            except ET.ParseError:
                pass

        if fd:
            print("[SAML] Got SAML result tags:", fd)
            self.saml_result.update(fd)

        if self.check_done():
            self.app.quit()

    def check_done(self):
        if "saml-username" in self.saml_result and (
            "prelogin-cookie" in self.saml_result
            or "portal-userauthcookie" in self.saml_result
        ):
            print("[SAML] Got all required SAML headers, done.")
            self.success = True
            return True
        return False


class TLSAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, verify=True):
        self.verify = verify
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.set_ciphers("DEFAULT:@SECLEVEL=1")
        ssl_context.options |= 1 << 2  # OP_LEGACY_SERVER_CONNECT

        if not self.verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        if hasattr(ssl_context, "keylog_filename"):
            sslkeylogfile = environ.get("SSLKEYLOGFILE")
            if sslkeylogfile:
                ssl_context.keylog_filename = sslkeylogfile

        self.poolmanager = urllib3.PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, ssl_context=ssl_context
        )


def parse_args(args=None):
    pf2clientos = dict(linux="Linux", darwin="Mac", win32="Windows", cygwin="Windows")
    clientos2ocos = dict(Linux="linux-64", Mac="mac-intel", Windows="win")
    default_clientos = pf2clientos.get(platform, "Windows")

    p = argparse.ArgumentParser()
    p.add_argument("server", help="GlobalProtect server (portal or gateway)")
    p.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        default=True,
        help="Ignore invalid server certificate",
    )
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-C",
        "--cookies",
        default="~/.gp-saml-gui-cookies",
        help="Use and store cookies in this file (instead of default %(default)s)",
    )
    x.add_argument(
        "-K",
        "--no-cookies",
        dest="cookies",
        action="store_const",
        const=None,
        help="Don't use or store cookies at all",
    )
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-g",
        "--gateway",
        dest="interface",
        action="store_const",
        const="gateway",
        default="portal",
        help="SAML auth to gateway",
    )
    x.add_argument(
        "-p",
        "--portal",
        dest="interface",
        action="store_const",
        const="portal",
        help="SAML auth to portal (default)",
    )
    g = p.add_argument_group("Client certificate")
    g.add_argument(
        "-c",
        "--cert",
        help="PEM file containing client certificate (and optionally private key)",
    )
    g.add_argument(
        "--key",
        help="PEM file containing client private key (if not included in same file as certificate)",
    )
    g = p.add_argument_group("Debugging and advanced options")
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-v",
        "--verbose",
        default=1,
        action="count",
        help="Increase verbosity of explanatory output to stderr",
    )
    x.add_argument(
        "-q",
        "--quiet",
        dest="verbose",
        action="store_const",
        const=0,
        help="Reduce verbosity to a minimum",
    )
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-x",
        "--external",
        action="store_true",
        help="Launch external browser (for debugging)",
    )
    x.add_argument(
        "-P",
        "--pkexec-openconnect",
        action="store_const",
        dest="exec",
        const="pkexec",
        help="Use PolicyKit to exec openconnect",
    )
    x.add_argument(
        "-S",
        "--sudo-openconnect",
        action="store_const",
        dest="exec",
        const="sudo",
        help="Use sudo to exec openconnect",
    )
    x.add_argument(
        "-E",
        "--exec-openconnect",
        action="store_const",
        dest="exec",
        const="exec",
        help="Execute openconnect directly (advanced users)",
    )
    g.add_argument(
        "-u",
        "--uri",
        action="store_true",
        help="Treat server as the complete URI of the SAML entry point, rather than GlobalProtect server",
    )
    g.add_argument(
        "--clientos",
        choices=set(pf2clientos.values()),
        default=default_clientos,
        help="clientos value to send (default is %(default)s)",
    )
    p.add_argument(
        "-f",
        "--field",
        dest="extra",
        action="append",
        default=[],
        help='Extra form field(s) to pass to include in the login query string (e.g. "-f magic-cookie-value=deadbeef01234567")',
    )
    p.add_argument(
        "--allow-insecure-crypto",
        dest="insecure",
        action="store_true",
        help="Allow use of insecure renegotiation or ancient 3DES and RC4 ciphers",
    )
    p.add_argument(
        "--user-agent",
        "--useragent",
        default="PAN GlobalProtect",
        help="Use the provided string as the HTTP User-Agent header (default is %(default)r, as used by OpenConnect)",
    )
    p.add_argument(
        "--no-proxy", action="store_true", help="Disable system proxy settings"
    )
    p.add_argument(
        "openconnect_extra",
        nargs="*",
        help="Extra arguments to include in output OpenConnect command-line",
    )
    args = p.parse_args(args)

    args.ocos = clientos2ocos[args.clientos]
    args.extra = dict(x.split("=", 1) for x in args.extra)

    if args.cookies:
        args.cookies = path.expanduser(args.cookies)

    if args.cert and args.key:
        args.cert, args.key = (args.cert, args.key), None
    elif args.cert:
        args.cert = (args.cert, None)
    elif args.key:
        p.error("--key specified without --cert")
    else:
        args.cert = None

    return p, args


def main(args=None):
    p, args = parse_args(args)

    s = requests.Session()
    if args.insecure:
        s.mount("https://", TLSAdapter(verify=args.verify))
    s.headers["User-Agent"] = (
        "PAN GlobalProtect" if args.user_agent is None else args.user_agent
    )
    s.cert = args.cert

    if2prelogin = {
        "portal": "global-protect/prelogin.esp",
        "gateway": "ssl-vpn/prelogin.esp",
    }
    if2auth = {"portal": "global-protect/getconfig.esp", "gateway": "ssl-vpn/login.esp"}

    # query prelogin.esp and parse SAML bits
    if args.uri:
        sam, uri, html = "URI", args.server, None
    else:
        endpoint = "https://{}/{}".format(args.server, if2prelogin[args.interface])
        data = {
            "tmp": "tmp",
            "kerberos-support": "yes",
            "ipv6-support": "yes",
            "clientVer": 4100,
            "clientos": args.clientos,
            **args.extra,
        }
        if args.verbose:
            print(
                "Looking for SAML auth tags in response to %s..." % endpoint,
                file=sys.stderr,
            )
        try:
            res = s.post(endpoint, verify=args.verify, data=data)
        except Exception as ex:
            rootex = ex
            while True:
                if isinstance(rootex, ssl.SSLError):
                    break
                elif not rootex.__cause__ and not rootex.__context__:
                    break
                rootex = rootex.__cause__ or rootex.__context__
            if isinstance(rootex, ssl.CertificateError):
                p.error(
                    "SSL certificate error (try --no-verify to ignore): %s" % rootex
                )
            elif isinstance(rootex, ssl.SSLError):
                p.error(
                    "SSL error (try --allow-insecure-crypto to ignore): %s" % rootex
                )
            else:
                raise
        xml = ET.fromstring(res.content)
        if xml.tag != "prelogin-response":
            p.error(
                "This does not appear to be a GlobalProtect prelogin response\nCheck in browser: {}?{}".format(
                    endpoint, urlencode(data)
                )
            )
        status = xml.find("status")
        if status is not None and status.text != "Success":
            msg = xml.find("msg")
            if (
                msg is not None
                and msg.text == "GlobalProtect {} does not exist".format(args.interface)
            ):
                p.error(
                    "{} interface does not exist; specify {} instead".format(
                        args.interface.title(),
                        "--portal" if args.interface == "gateway" else "--gateway",
                    )
                )
            else:
                p.error(
                    "Error in {} prelogin response: {}".format(args.interface, msg.text)
                )
        sam = xml.find("saml-auth-method")
        sr = xml.find("saml-request")
        if sam is None or sr is None:
            p.error(
                "{} prelogin response does not contain SAML tags (<saml-auth-method> or <saml-request> missing)\n\n"
                "Things to try:\n"
                "1) Spoof an officially supported OS (e.g. --clientos=Windows or --clientos=Mac)\n"
                "2) Check in browser: {}?{}".format(
                    args.interface.title(), endpoint, urlencode(data)
                )
            )
        sam = sam.text
        sr = a2b_base64(sr.text).decode()
        if sam == "POST":
            html, uri = sr, None
        elif sam == "REDIRECT":
            uri, html = sr, None
        else:
            p.error("Unknown SAML method (%s)" % sam)

    # Launch external browser for debugging if requested
    if args.external:
        print(
            "Got SAML %s, opening external browser for debugging..." % sam,
            file=sys.stderr,
        )
        import webbrowser

        if html:
            uri = "data:text/html;base64," + b2a_base64(html.encode()).decode()
        webbrowser.open(uri)
        raise SystemExit

    # Use PyQt5 for SAML interactive login
    if args.verbose:
        print("Got SAML %s, opening PyQt5 WebKit browser..." % sam, file=sys.stderr)

    app = QtWidgets.QApplication(sys.argv)
    slv = SAMLLoginView(
        uri, html, args
    )  # Pass the URI or HTML to the SAMLLoginView class
    # slv.show()
    app.exec_()

    if slv.closed:
        print("Login window closed by user.", file=sys.stderr)
        p.exit(1)
    if not slv.success:
        p.error("Login window closed without producing SAML cookies.")

    # Extract response and convert to OpenConnect command-line
    un = slv.saml_result.get("saml-username")
    server = slv.saml_result.get("server", args.server)

    for cn, ifh in (
        ("prelogin-cookie", "gateway"),
        ("portal-userauthcookie", "portal"),
    ):
        cv = slv.saml_result.get(cn)
        if cv:
            break
    else:
        cn = ifh = None
        p.error("Didn't get an expected cookie. Something went wrong.")

    urlpath = args.interface + ":" + cn
    openconnect_args = [
        "--protocol=gp",
        "--user=" + un,
        "--os=" + args.ocos,
        "--usergroup=" + urlpath,
        "--passwd-on-stdin",
        server,
    ] + args.openconnect_extra

    if args.insecure:
        openconnect_args.insert(1, "--allow-insecure-crypto")
    if args.user_agent:
        openconnect_args.insert(1, "--useragent=" + args.user_agent)
    if args.cert:
        cert, key = args.cert
        if key:
            openconnect_args.insert(1, "--sslkey=" + key)
        openconnect_args.insert(1, "--certificate=" + cert)
    if args.no_proxy:
        openconnect_args.insert(1, "--no-proxy")

    openconnect_command = """    echo {} |\n        sudo openconnect {}""".format(
        quote(cv), " ".join(map(quote, openconnect_args))
    )

    if args.verbose:
        if server != args.server and not args.uri:
            print(
                "IMPORTANT: Redirected from {} to {}. Try both.".format(
                    args.server, server
                ),
                file=sys.stderr,
            )
        if ifh != args.interface and not args.uri:
            print(
                "IMPORTANT: Started with {} but got cookie for {}. Try both.".format(
                    args.interface, ifh
                ),
                file=sys.stderr,
            )
        print(
            "SAML response converted to OpenConnect command line invocation:",
            file=sys.stderr,
        )
        print(openconnect_command, file=sys.stderr)

    if args.exec:
        print(
            "Launching OpenConnect with {}, equivalent to:\n{}".format(
                args.exec, openconnect_command
            ),
            file=sys.stderr,
        )
        with tempfile.TemporaryFile("w+") as tf:
            tf.write(cv)
            tf.flush()
            tf.seek(0)
            dup2(tf.fileno(), 0)
        cmd = ["openconnect"] + openconnect_args
        if args.exec == "pkexec":
            cmd = ["pkexec", "--user", "root"] + cmd
        elif args.exec == "sudo":
            cmd = ["sudo"] + cmd
        execvp(cmd[0], cmd)
    else:
        varvals = {
            "HOST": quote("https://%s/%s" % (server, urlpath)),
            "USER": quote(un),
            "COOKIE": quote(cv),
            "OS": quote(args.ocos),
        }
        print("\n".join("%s=%s" % pair for pair in varvals.items()))


if __name__ == "__main__":
    main()
