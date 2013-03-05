squid2radius
============

squid2radius analyzes your squid `access.log` file, and reports usage information to a RADIUS server using `Accounting-Request` as defined in RFC 2866.

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
sudo pip2 install pyrad hurry.filesize
```

Upgrading to v1.0
-----------------

### New dependency `hurry.filesize`

Note that an dependency `hurry.filesize` is required since Version 1.0.  Run 
`sudo pip2 install hurry.filesize` to install it.


Usage
-----

```
usage: squid2radius.py [-h] [--version] [-p RADIUS_ACCT_PORT]
                       [--radius-nasid RADIUS_NASID] [--squid-path SQUID_PATH]
                       [--exclude-pattern EXCLUDE_PATTERN] [--dry-run]
                       [--no-rotation]
                       logfile_path radius_server radius_secret
```

For instance, run like this if you have access log file at `/var/log/squid/access.log`, RADIUS server running at `localhost` with secret set to `testing123`:

```bash
sudo python2 squid2radius.py /var/log/squid/access.log localhost testing123
```

It is certainly a good idea to make a cron job for this.

You should also read [SquidFaq/SquidLogs](http://wiki.squid-cache.org/SquidFaq/SquidLogs#access.log) to make sure your log files are in reasonable sizes.

### --exclude-pattern

If for some reason you need to prevent usage information of certain user from being sent to the RADIUS server, there is an argument for that!  Use `--exclude-pattern="(girl|boy)friend"` and squid2radius won't send usage of either your `girlfriend` or `boyfriend` to the RADIUS server.

### --dry-run

If the script is called with this argument, no data will be sent to the server.

### --no-rotation

By default squid2radius calls `squid -k rotate` to make squid rotate your log files right after we are done counting usage data, in order to ensure usage data accuracy by not counting any log lines more than once next time you run it.  If this is troublesome in your setup, you can add `--no-rotation` argument to disable this behavior.

Note
----

The script assumes that you are using the default [Squid native access.log format](http://wiki.squid-cache.org/Features/LogFormat#squid) on first ten columns of your log file.  If you need custom columns, add them after the default ones.

