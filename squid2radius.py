import sys
import argparse
from subprocess import call
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary


parser = argparse.ArgumentParser(description='Analyze squid log by user ' \
                                             'and upload result to RADIUS serv')
parser.add_argument('logfile_path', help='logfile to analyze')
parser.add_argument('radius_server')
parser.add_argument('radius_secret')
parser.add_argument('-p', '--radius-acct-port', default='1812')
parser.add_argument('--radius-nasid', default='squid')
parser.add_argument('-r', '--rotate', action='store_true', help='rotate log when done')
parser.add_argument('--squid-path', default='/usr/sbin/squid')
args = parser.parse_args()


logfile = open(args.logfile_path)
print logfile

sys.stdout.write("Analyzing")
sum_bytes = {}
for i, line in enumerate(logfile):
  if i % 1000 == 0: sys.stdout.write('.')
  
  # http://wiki.squid-cache.org/Features/LogFormat
  _, _, _, _, num_bytes, _, _, rfc931, _, _ = line.split()
  
  if rfc931 == '-': continue
  
  try:
    sum_bytes[rfc931] = sum_bytes[rfc931] + int(num_bytes)
  except KeyError:
    sum_bytes[rfc931] = int(num_bytes)


print "\nSetting up RADIUS server..."
srv = Client(server=args.radius_server, secret=args.radius_secret,
             dict=Dictionary("dictionary"))


print "Sending..."
for username, total_bytes in sum_bytes.iteritems():
  sys.stdout.write(username + ' ' + str(total_bytes))
  sys.stdout.write('.')

  req = srv.CreateAcctPacket()
  req['NAS-Identifier'] = args.radius_nasid
  req['Acct-Output-Octets'] = total_bytes

  sys.stdout.write('.')
  reply = srv.SendPacket(req)

  if not reply.code == pyrad.packet.AccountingResponse:
    raise Exception("mysterious RADIUS server response")

  sys.stdout.write('.')


print "\nRotating squid log..."
call(args.squid_path, '-k rotate')

