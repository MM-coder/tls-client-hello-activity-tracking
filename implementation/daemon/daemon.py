import datetime
import asyncio
import psycopg2.pool
import re

from scapy.all import AsyncSniffer, load_layer
from scapy.layers.l2 import Ether
from scapy.layers.tls.extensions import ServerName
from urllib.parse import urlparse

# Config

threshold = 15
database_url = ''

# Globals

load_layer('tls')
captured_packets = list()
filter_ = 'tcp dst port 443 and (tcp[((tcp[12] & 0xf0) >> 2)] = 0x16 && (tcp[((tcp[12] & 0xf0) >> 2)+5] = 0x01))'

parsed_url = urlparse(database_url)
username = parsed_url.username
password = parsed_url.password
database = parsed_url.path[1:]
hostname = parsed_url.hostname

pool = psycopg2.pool.ThreadedConnectionPool(0, 100, user=username, password=password, host=hostname, database=database)


# Classes

class Handshake(object):
    """
       Represents a parsed handshake that was sniffed

        Attributes
        ----------
        mac : str
            MAC (Media Access Control) address of the device that initiated the handshake

        url : str
            URL decoded from the ServerName parameter of the Client Hello

        time: int
            Time the packet was processed
    """

    def __init__(self, mac: str, url: str, time: int):
        self.mac = mac
        self.url = url
        self.time = time


# Functions

def initialize_database() -> None:
    connection = pool.getconn()
    cursor = connection.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS Packets(
                        mac TEXT,
                        url TEXT,
                        time INTEGER)""")
    connection.commit()
    cursor.close()


def check_subdomain_validity(list_: list) -> bool:
    # Iterates through a list and checks if any element has a subdomain with less than 3 chars
    # Also checks the subdomain for numbers and the amount of '-' in it
    # This is intended to capture domains like cse.google.com or d.joinhoney.com 123.amazonaws.com
    # or prod-video-cms-rt-microsoft-com.akamaized.net

    list_ = list_[:len(list_) - 2]  # Exclude the gTLD and the domain name
    list_.remove('www') if 'www' in list_ else list_  # Check if www is in the list and remove it if it is

    for element in list_:
        if len(element) <= 3 or re.search(r"[0-9]", element) or element.count('-') >= 2:
            return True
    return False


def filter_packets(packets: list) -> list:
    # Function to filter packets to ignore CDNs, APIs, etc
    # Returns a list of Handshake objects

    # Simple filter, should catch most urls

    parsed_objects = list()
    with open('regex.list', 'r') as f:
        lines = f.read().splitlines()  # Reads the file and removes the newlines
        for packet in packets:
            url = packet.getlayer(ServerName).servername.decode('UTF-8')  # Get the server name from the packet
            for line in lines:
                if re.search(re.compile(line, re.DOTALL), url) or check_subdomain_validity(
                        url.split('.')):  # Check against the regex and the subdomain tests
                    break
            mac = packet.getlayer(Ether).src
            parsed_objects.append(
                Handshake(mac, url, int(datetime.datetime.now().timestamp())))  # Create a handsake object
    return parsed_objects


def push_packets_to_database(handshakes: list) -> None:
    if handshakes:  # Is the list not empty?
        connection = pool.getconn()
        cursor = connection.cursor()
        for handshake in handshakes:
            cursor.execute("INSERT INTO Packets(mac, url, time) VALUES (%s, %s, %s)",
                           (handshake.mac, handshake.url, handshake.time))
            connection.commit()
        cursor.close()
        pool.putconn(connection)


t = AsyncSniffer(iface="wlp19s0", prn=lambda x: captured_packets.append(x),
                 filter=filter_)  # Create a asyncrounous sniffer

if __name__ == '__main__':
    initialize_database()  # Initalize the database
    t.start()  # Start sniffing

    while True:
        if len(captured_packets) >= threshold:  # Check if the packets have accumulated
            list_ = captured_packets.copy()  # Take a copy of the list
            captured_packets = list()  # Reinitialize the list
            list_ = [p for i, p in enumerate(list_[:-1]) if
                     p.getlayer(ServerName).servername != list_[i + 1].getlayer(ServerName).servername]

            # WARN(Mauro): This function is blocking, and if it takes too long it might cause the next database request
            #              to be larger, consider upping the threshold variable if this becomes a problem.

            push_packets_to_database(filter_packets(list_))  # Push packets to database
