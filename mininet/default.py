from .start import start


if __name__ == '__main__':
    """To spin up this mininet topology, simply run this as a normal python script with sudo permissions."""
    start("python -m SimpleHTTPServer 80 &")
