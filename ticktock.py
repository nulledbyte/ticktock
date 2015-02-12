#! /usr/bin/env python

# Title:        TickTock
# Description:  Enumerate user names through observing and comparing response time delays from a web server.
# Author:       NulledByte
# Version:      1.0
# Date:         2014-02-11
# License:      MIT License

from __future__ import division
import argparse
import pycurl
import matplotlib.pyplot as plt
import logging
import statistics

from decimal import getcontext
from io import BytesIO

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

LOG_FILENAME = "ticktock.log"
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',)


# Configure arguments for the Python script.
parser = argparse.ArgumentParser(description='Identify username timing attacks')
parser.add_argument('--target', help='The login page')
parser.add_argument('--valid_post', help='The POST data for a valid user')
parser.add_argument('--invalid_post', help='The POST data for an invalid user')
parser.add_argument('--attempts', help="The number of authentication attempts to process.", default=50, type=int)
parser.add_argument('--time_delay', help="The time in milliseconds between authentication requests", default=50, type=int)
parser.add_argument('--precision', help="The precision when rounding.", default=3, type=int)
args = parser.parse_args()

logging.debug("Passed arguments: {0}".format(args))

# Decimal precision
getcontext().prec = 4


def send_request(target, data, method='POST'):
    """
    Create a native CURL HTTP connection to the site, and POST the data. Return the timing information.
    :type target: str
    :type data: str
    :type method: str
    :return:
    """

    # Store the HTTP response
    buffer = BytesIO()

    curl = pycurl.Curl()

    # Remove this!
    curl.setopt(pycurl.SSL_VERIFYPEER, 0)
    curl.setopt(pycurl.SSL_VERIFYHOST, 0)

    curl.setopt(pycurl.URL, target)
    curl.setopt(pycurl.POSTFIELDS, data)
    curl.setopt(pycurl.WRITEDATA, buffer)
    curl.perform()

    return curl


def extract_timings(request, precision):

    """
    Retrieve the timings for each stage of the HTTP communication and store them as a rounded value
    :type request: pycurl.Curl
    :type precision: int
    :return: dict
    """

    transfer = {
        'DNSLookup': round(request.getinfo(pycurl.NAMELOOKUP_TIME), precision),
        'TCPConnectionTime': round(request.getinfo(pycurl.CONNECT_TIME), precision),
        'AppConnectionTine': round(request.getinfo(pycurl.APPCONNECT_TIME), precision),
        'StartTransferTime': round(request.getinfo(pycurl.STARTTRANSFER_TIME), precision),
        'TotalTime': round(request.getinfo(pycurl.TOTAL_TIME), precision)
    }

    return transfer

metrics = {"valid": list(), "invalid": list()}

for i in range(args.attempts):

    # Issue the Curl requests for both invalid and valid usernames
    valid_handle = send_request(args.target, args.valid_post)
    valid_results = extract_timings(valid_handle, args.precision)
    valid_handle.close()

    invalid_handle = send_request(args.target, args.invalid_post)
    invalid_results = extract_timings(invalid_handle, args.precision)
    invalid_handle.close()

    logging.debug("Processed {0} / {1} requests...".format(i, args.attempts))

    metrics['valid'].append(valid_results)
    metrics['invalid'].append(invalid_results)

# Generate the data lists for the plotting library
y_axis_valid = [metric['StartTransferTime'] / metric['TotalTime'] for metric in metrics['valid']]
y_axis_invalid = [metric['StartTransferTime'] / metric['TotalTime'] for metric in metrics['invalid']]

logging.info("Valid login response average: {0}".format(statistics.mean(y_axis_valid)))
logging.info("Invalid login response average: {0}".format(statistics.mean(y_axis_invalid)))

# Generate a sequential list, representing the request number for the x axis
x_axis = range(1, args.attempts + 1)

# General graph options and format
plt.title("Response Times for Valid / Invalid User Names")
plt.ylabel('Response Time (ms)')
plt.xlabel('Request Number (#)')
plt.minorticks_on()

# Plot all the results with color (invalid=red, valid=blue)
plt.plot(x_axis, y_axis_valid, 'b')
plt.plot(x_axis, y_axis_invalid, 'r')

# Manually set the axis scale to have a 5% buffer and show the graph
plt.axis([1, args.attempts,
          min(y_axis_valid) - (min(y_axis_valid) * 0.05),
          max(y_axis_valid) + (max(y_axis_valid) * 0.05)])

plt.show()
