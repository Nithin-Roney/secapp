import requests

def custom_header_scan(url):
    try:
        response = requests.get(url)
        return response.headers
    except Exception as e:
        return {'error': str(e)}

def custom_port_scan(url):
    import socket
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    common_ports = [80, 443, 21]
    open_ports = []

    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((domain, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def custom_reverse_ip_lookup(url):
    import requests
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={domain}")
    return response.text.split('\n') if response.status_code == 200 else [response.text]
