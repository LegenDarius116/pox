import argparse
import requests


def main(serv, n, v):
    """Uses requests instead of curl. May be cleaner."""
    if n < 1:
        raise ValueError("-n must be a positive value")

    for i in range(args.n):
        requests.get("http://{}".format(serv))
        if v:
            print(i)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple TG Script using requests')
    parser.add_argument("-s", type=str, help="address of server", required=True)
    parser.add_argument("-n", type=int, help="number of times to send GET request to server", required=True)
    parser.add_argument('-v', type=bool, help="verbose flag. show output if this is here")
    args = parser.parse_args()

    main(args.s, args.n, args.v)
