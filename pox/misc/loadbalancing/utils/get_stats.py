import pycurl
from StringIO import StringIO
import argparse
import time
import csv

parser = argparse.ArgumentParser(description='Command line tool for curling and getting statistics')
parser.add_argument("-s", type=str, help="address of server")
parser.add_argument("-n", type=int, help="number of times to curl server")
parser.add_argument("-d", type=int, help="delay in milliseconds between curling again")
parser.add_argument("-csv",type=str, help="name of the csv file for logging")
args = parser.parse_args()



server = args.s
num_of_times = args.n
delay = args.d
csv_filename = args.csv
if csv_filename is None:
    csv_filename = "data_taken.csv"
#f = open("stats.log", "w")

server_addr = "http://{}".format(args.s)
with open(csv_filename, mode='w') as csv_file:
    csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    first_row = ['curl_num', 'total_time', 'connect_time', 'pretransfer_time', 'redirect_time', 'starttransfer-time']
    csv_writer.writerow(first_row)
    for i in range(num_of_times):
        buffer = StringIO()
        c = pycurl.Curl()
        c.setopt(c.URL, server_addr)
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.VERBOSE, True)
        c.perform()


        body = buffer.getvalue()

        m = {}
        m['total-time'] = c.getinfo(pycurl.TOTAL_TIME)
        m['connect-time'] = c.getinfo(pycurl.CONNECT_TIME)
        m['pretransfer-time'] = c.getinfo(pycurl.PRETRANSFER_TIME)
        m['redirect-time'] = c.getinfo(pycurl.REDIRECT_TIME)
        m['starttransfer-time'] = c.getinfo(pycurl.STARTTRANSFER_TIME)

        #c.close()
        row = [i, m['total-time'], m['connect-time'],m['pretransfer-time'], m['redirect-time'], m['starttransfer-time']]
        csv_writer.writerow(row)
        #f.write("curl {}\n".format(i))
        #f.write("{}\n".format(m))
        time.sleep(float(delay)/1000)

#f.close()
