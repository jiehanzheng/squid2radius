squid2radius
============

squid2radius analyzes your squid `access.log` file, and report it to a RADIUS server using `Accounting-Request` as defined in RFC 2866.

After analyzing is finished, it calls squid to rotate your log file so that no lines will be counted more than once.

Installation
------------

### Clone Git repo

```bash
git clone git://github.com/jiehanzheng/squid2radius.git
```

### Install dependencies

```bash
# install pip for python2, command varies if you are on a different OS
sudo pacman -S python2-pip

# install pyrad, command varies if you are on a different OS
pip2 install pyrad
```

Usage
-----

```
usage: squid2radius.py [-h] [-p RADIUS_ACCT_PORT]
                       [--radius-nasid RADIUS_NASID] [-r]
                       [--squid-path SQUID_PATH]
                       logfile_path radius_server radius_secret

```

For instance, run like this if you have access log file at `/var/log/squid/access.log`, RADIUS server running at `localhost` with secret set to `testing123`:

```bash
python2 squid2radius.py /var/log/squid/access.log localhost testing123
```

It is certainly a good idea to make a cron job for this.

You should also read [SquidFaq/SquidLogs](http://wiki.squid-cache.org/SquidFaq/SquidLogs#access.log) to make sure your log files are in reasonable sizes.
