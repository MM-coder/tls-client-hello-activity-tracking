import click
import psycopg2.pool

from urllib.parse import urlparse
from prettytable import PrettyTable

database_url = ''

parsed_url = urlparse(database_url)
username = parsed_url.username
password = parsed_url.password
database = parsed_url.path[1:]
hostname = parsed_url.hostname

pool = psycopg2.pool.ThreadedConnectionPool(0, 100, user=username, password=password, host=hostname, database=database)


@click.group()
def commands():
    pass


@commands.group()
def group():
    """Create and view groups"""
    pass


@group.command()
def list():
    """List groups created by the user"""
    conn = pool.getconn()
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM groups""")
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    table = PrettyTable()
    table.field_names = ['MACs', 'Name']
    for i in data:
        table.add_row(i)
    click.echo(table)


@group.command()
@click.argument('name')
@click.argument('MACs')
def create(name, macs):
    """Create a group"""
    if name and macs:
        conn = pool.getconn()
        cursor = conn.cursor()
        macs = macs.split(',')
        cursor.execute("""INSERT INTO Groups(addresses, name) VALUES (%s,%s)""", (macs, name))
        conn.commit()
        cursor.close()
        click.echo(f'Created the group {name}')


@commands.group()
def packets():
    """View packets sniffed by the daemon"""
    pass


@packets.command()
def list():
    """List all packets sniffed by the daemon"""
    conn = pool.getconn()
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM packets""")
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    table = PrettyTable()
    table.field_names = ['MAC', 'URL', 'Timestamp']
    for i in data:
        table.add_row(i)
    click.echo(table)


@packets.command()
@click.argument('MAC')
def search(mac):
    """Display all packets sent by a certain MAC address"""
    conn = pool.getconn()
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM packets where mac=%s""", (mac,))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    table = PrettyTable()
    table.field_names = ['MAC', 'URL', 'Timestamp']
    for i in data:
        table.add_row(i)
    click.echo(table)


@packets.command()
@click.argument('group')
def group(group):
    """List packets from a certain group"""
    conn = pool.getconn()
    cursor = conn.cursor()
    cursor.execute("""SELECT addresses FROM groups where name=%s""", (group,))
    macs = cursor.fetchone()[0]
    cursor.execute("""SELECT * FROM packets where mac = ANY (%s)""", (macs,))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    table = PrettyTable()
    table.field_names = ['MAC', 'URL', 'Timestamp']
    for i in data:
        table.add_row(i)
    click.echo(table)


if __name__ == '__main__':
    commands(prog_name='client')
