# /*    all lines except VERSION are C comments
package IPTables::IPv4::DBTarpit;
use vars qw($VERSION);
$VERSION = do { q| */ char version[] = "dbtarpit 0.23, 12-6-03"; /* | =~ /(\d+)\.(\d+)/; sprintf("%d.%02d",$1,$2)};
# returns $VERSION which is non-zero
__END__

=head1 NAME

dbtarpit - extension for Linux iptables

distributed as perl module IPTables::IPv4::DBTarpit

=head1 SYNOPSIS

  dbtarpit [options]...

=head1 DESCRIPTION and OPERATION

There is no perl module for C<dbtarpit>. This is a documentation shell.

See L<IPTables::IPv4::DBTarpit::Tools>
to manipulate and examine the C<dbtarpit> database(s).

C<dbtarpit> is a B<C> daemon that uses libipq (the Linux iptables userspace packet queuing
library) to examine packets that match a filter criteria and tarpit 
those connections whose IP addresses are found in its database.

Currently it is only supported on Linux with iptables, however the database
library and Tools will build and install on any os that supports Perl.

The C<dbtarpit> database is implemented using the Berkeley DB database found 
in all Linux distributions. C<dbtarpit> is configured for 
B<concurrent> use of the database, allowing similtaneous access and update 
of the database by other applications.

C<dbtarpit> checks the packet IP address against its B<tarpit> database for a match. If
a match is found the B<tarpit> database is updated with the most recent connection attempt 
time, the packet is dropped, and the connection tarpitted.
Optionally, packet IP addresses that are not found in the B<tarpit> database are logged in 
the B<archive> database with the most recent connect time for later examination
by other applications.

When used to defend against denial of service attacks, the tarpit is highly
effective because it eliminates the traffic from the attacking site by
stopping the transmission of data packets at the remote IP stack.

To defend against denial of service attacks for protocols other than TCP/IP,
DBTarpit can optionally be configured to drop packets for any connection found in the
B<tarpit> database. See the B<-X> switch description below.

=head1 INSTALLATION

To build the C<dbtarpit> daemon and tools, type the following:

  perl Makefile.PL
  make
  make test
  make install

B<To restore the default directory configurations type:>

  rm config.db

B<Adjust the permissions for "dbtarpit" and its installation directories.
This is not done automatically since it may involve system directories.>

In the iptables configuration file, place the filter
for C<dbtarpit> as the first entry in the INPUT chain.
do not insert other entries ahead of this rule.

  i.e.  
  IPTABLES = "/usr/local/spamcannibal/bin/iptables"
  ANYWHERE = "0/0"
  ...

  $IPTABLES -A INPUT -p tcp -s $ANYWHERE --dport 10025 -j QUEUE

This rule will send tcp packets destined for port 10025 from 
anywhere to the C<dbtarpit> daemon. If the IP address of the
packet is not found in the database, the packet is returned
to the chain untouched. If the IP address is found in the 
database, the packet is dropped and the connection tarpitted.

WARNING: if the dbtarpit daemon is not running, packets destined for
port 10025 (or whatever you select) are silently dropped by IPTABLES.

The Berkeley DB environment and database file will be created automatically,
however you may wish to use IPTables::IPv4::DBTables::Tools. 
Adjust the permissions of these files so that they
are accessible by the various applications that will be using the
information in the databases. Pay particular attention to the permissions on
the files. Because the C<tarpit> daemon has only concurrent access to the
database, applications should not write applications which use  db->cursor
operations these can block dameon access for normal put and sync operations. 
Instead, use repetitive read-by-record-number operations to gain sequential access  
to the data.

Lastly, copy B<rc.dbtarpit> to your startup directory so it is executed 
immediately following rc.iptables at boot up as:

  rc.dbtarpit start

Read the B<rc.dbtarpit> documentation, first by typing:

  perdoc -U ./rc.dbtarpit

and then by looking at the comments at the beginning of the file.

See L<IPTables::IPv4::DBTarpit::Config> to find out how to pass the DBTarpit
configuration information directly to your perl scripts.

=head1 DEPENDENCIES

  libdbtarpit 0.0.0 (included with this distribution)

  Berkeley DB 2.6.4 or better http://www.sleepycat.com/

  LIBNET 1.0 http://www.packetfactory.net/libnet

  Linux kernel with iptables (libipq)

  Network packet filtering (replaces ipchains) 
	(CONFIG_NETFILTER) [Y/n/?] y

It is recommended that you not use connection
tracking since each tarpitted connection will
consume resources. If the tarpit is run on a 
linux box used as a firewall, then this is
unavoidable.

  connection tracking (required for masq/NAT) 
	(CONFIG_IP_NF_CONNTRACK) [Y/m/n/?] n

  Userspace queueing via NETLINK (EXPERIMENTAL)
	(CONFIG_IP_NF_QUEUE) [Y/m/n/?] y or m

  ----------------------------------------

COMMENT: Our firewall runs with...
  connection tracking (required for masq/NAT)
        (CONFIG_IP_NF_CONNTRACK) [Y/m/n/?] Y

I've seen as many as several thousand threads in the tarpit with affecting
performance on an aging 486 with not much memory. This doesn't seem to be a
big deal, but I've seen it mentioned by those with better insight into
potential problems than me.

=head1 OPTIONS - short version

 Options:
   -a           : Allow all connections
   -b           : Log bandwidth usage to syslog
   -d           : Do NOT detach process.
   -D           : Print packet debug info (like tcpdump) in/out
   -k           : Do not respond to SYN/ACKs (Note 1)
   -l           : Log activity to syslog (Note 2)
   -o           : Output to stdout instead of syslog (Note 3)
   -O           : Same as -o w/time output in seconds since epoch
   -p maxrate   : "Persist" state capture connect attempts (Note 4)
   -P           : Persist mode capture only.
   -R           : Soft restart - Wait while recapturing active connects
   -t datasize  : Set connection throttling size in bytes (default 10)
   -T           : Test mode - Prints out debug info but DOES NOT RUN
   -u fifoname  : Log to fifo (Note 5)
   -v           : Verbosely log activity to syslog (Note 2)
   -V           : Print version information and exit
   -x           : Disable IP capture, just drop connection
   -X           : Drop non-TCP/IP connections found in database
   -L           : tarpit Localhost addresses 127.x.x.x (normally disabled)
   -r /path     : Alternate DB root directory (default "/var/run/dbtarpit)
   -f filename  : Alternate primary DB file name (default "tarpit")
   -s filename  : Optional "connected IP's" database name
   -h           : Print this help information
   -?           : Print this help information

 Note 1:
  By default, dbtarpit responds to an inbound SYN/ACK with an RST
  The -k option eliminates this behavior.
 Note 2:
  'kill -USR1 <dbtarpit_PID>' to toggle logging on and off.
  If logging was not enabled at start this sets the '-l' flag
  If logging (-l | -v) are set this saves the value and turns off logging
  If logging is presently toggled off it restores the saved level (-l | -v)
 Note 3:
  This sends log information to stdout rather than to syslog.  This 
  option also implies and sets the -d option (Do NOT detach process). 
  Silently ignored if '-u' is already present.
 Note 4:
  dbtarpit will permanently capture connect attempts within the limit of the
  maximum data rate specified (in bytes/sec).
 Note 5:
  Logs tarpit activity to a fifo in the DB root directory. This option 
  clears the '-o','-O', and '-d' flags. You still must use the (-l | -v)
  to set the log level. If you wish to use the '-d' flag, it must be 
  explicitly set after the '-u' option is invoked on the command line.
  '-u' logging uses the same format as the '-O' flag. 

=head1 OPTIONS - long version

=over 4

=item * -a

This will allow all connections. Connections are still added to the optional
"connected IP's", but no connections are tarpitted or dropped.

=item * -b

This will send an update on the current bandwidth being consumed by the
-p option to the log every minute.  If you're interested...  (Note: it
only works if you have -p enabled.)

=item * -d

Some people want to run C<dbtarpit> under the control of another process. This
keeps C<dbtarpit> from detaching and running as a daemon.

=item * -D

Print packet debug information similar to C<tcpdump -n -S -v -x -t port 10025>

  Incoming packet (iph + tcph) with flags info

	flags= 02  urg ack : psh  rst  syn  fin
	4500 003c 3dde 4000 4006 7825 c0a8 01be 
	c0a8 01aa da1b 2729 3da6 4ba0 0000 0000 
	a002 16d0 71b5 0000 0204 05b4 0402 080a 

  Outgoing packet
	4500 0028 adfa 0000 ff06 891c c0a8 01aa 
	c0a8 01be 2729 da1b 708f 808f 3da6 4ba1 
	5012 000a af64 0000 0000 60f7 ffbf 44f7 

  Note:	the incoming packet always has the flags at
	the top, the outgoing one never does.

=item * -k

By default, C<dbtarpit> will respond to a SYN/ACK packet
with a RST.  This is nice behavior, because it makes it difficult for
people to use your IP addresses to "spoof". If you
DON'T want this behavior, use the "-k" option to disable it.

=item * -l

Logs the IP addresses of hosts that are tarpitted. 

=item * -o

This gives you the option to have C<dbtarpit> log information go
to stdout instead of the syslog. This option also sets "-d", 
HOWEVER, "-o" is silently ignored if "-u" is already present.

=item * -O

The same as the "-o" option, but formats the time stamp as the number of
seconds since 00:00:00, Jan 1, 1970, make it easier for other 
"logfile analysis" programs to parse it. "-O" is silently ignored if "-u" is
already present.

=item * -p maxrate

If you specify this
flag and a maximum bandwidth, several things will happen.  First of all,
this forces data throttling to 5 bytes (see the "-t" option above).  Then,
when a connection is attempted, C<dbtarpit> will force the connection into what
is known as "persist" state.  In persist state, the connection  will NEVER
time out.  You'll literally hang onto the connecting thread until you stop or
they stop.  Running unchecked, this could have a very BAD effect on your
bandwidth, so C<dbtarpit> will make every effort to only allow this process to
take up the maximum bandwidth that you specify (in bytes/second).  If it
can't capture a connection, C<dbtarpit> will still tarpit it.  

Note: It'll stay pretty NEAR your MAXBW number.

=item * -P

Persist mode capture only.  This tries to limit bandwidth by only
persist capturing.  When we're at full bandwidth, standard tarpitting 
won't happen, but because the same "conversation" that leads to persist
capture also has the side-effect of tarpitting, when we're below our
set bandwidth, it's not really in effect.

=item * -R

"Soft Restart" mode. What this does is to hold off on any B<new> captures for 5 minutes, to let things
settle and to get the bandwidth calculations going correctly.

=item * -t datasize

This option sets the TCP window advertisement to limit the amount of data sent by the scanner.
The number of data bytes to allow per packet is passed as a parameter. (Default 10)

=item * -T

This prints a bunch of diagnostic information an exits.

=item * -u fifoname

Log to a fifo in the DB root directory (default
'/var/run/dbtarpit'). Do not use with the -o and -O flags, these 
flags are silently ignored if "-u" is already present on the command line.
Use the "-l" and "-v" flags to set the desired level of log activity.
If you wish to use the "-d" flag to not detach the daemon, it must be
explicitly specified after the "-u" option on the command line.
All tarpit activity is logged to the domain socket.

=item * -v

Logs verbosely. It logs IPs "captured", IPs "tarpitted",
and logs all activity from the "tarpitted" hosts.

=item * -V

Print version information and exit.

=item * -x

Disable tarpitting, just drop the incoming packet. This option
also sets "-x"

=item * -X

Drop non-TCP/IP connections found in tarpit database, log address if not
found (DoS defense mode).

=item * -L

Enable tarpiting of  Localhost addresses 127.x.x.x (normally disabled).
These addresses are normally used for administrative purposes.

=item * -r /path

Set the database root aka path to db environment home 

  (default: /var/run/dbtarpit)

=item * -f filename

Set the primary database name (default: tarpit)

=item * -s filename

Set the secondary database name (default: archive)

=item * -h

Print the "short" help information and exit.

=item * -?

Print the "short" help information and exit.

=back

=head1 DATABASE CONFIGURATION FILE [optional]

Usually used to increase database cache size.

Most of the configuration information that can be specified to 
DB_ENV methods can also be specified using a configuration file. 
If an environment home directory has been specified (done by default or
with the -r option to C<dbtarpit>) any file named DB_CONFIG in the 
database home directory will be read for lines of the format NAME VALUE.

One or more whitespace characters are used to delimit the two parts of 
the line, and trailing whitespace characters are discarded. All empty 
lines or lines whose first character is a whitespace or hash (#) 
character will be ignored. Each line must specify both the NAME and the 
VALUE of the pair. The specific NAME VALUE pairs are documented in the 
Berkeley DB manual for the corresponding methods.

See: http://www.sleepycat.com/docs/reftoc.html

=head1 DATABASE FORMAT

B<dbtarpit> and B<IPTables::IPv4::DBTarpit::Tools> use the Berkeley DB
database. The database is of type BTREE, opened for concurrent access and
sequential record access. Both of the database files have identical format.

  Files: tarpit, archive

  Key:	32 bit packed network address as produced by inet_aton
  Data:	32 bit unsigned integer, number of seconds since 1-1-70

  Database creation hints for 'C' api:

  * environment flags	*
    u_int32_t eflags = DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL;
  * db flags *
    u_int32_t dflags = DB_CREATE;
    u_int32_t info = DB_RECNUM;
    DBTYPE type = DB_BTREE;
    int mode = 0664;

environment and database open statements vary depending on the version of
BerkeleyDB used. See the code in bdb.c for specifics.

  Database creation hints for Perl api:

    my %env = (
        -Home   => $self->{dbhome},
        -Flags  => DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL,
    );

    $self->{"_db_${db}"}  = new BerkeleyDB::Btree
          -Filename     => $self->{dbfilename},
          -Flags        => DB_CREATE,
          -Property     => DB_RECNUM,
          -Env          => $self->{env}
          or die "Cannot open database $db: $! $BerkeleyDB::Error\n" ;

NOTE:  (in BIG LETTERS!)

Berkeley DB provides a "1" based numbering system for record numbers. i.e.
the first record number is "1". By contrast, perl-BerkeleyDB is a "0" based
numbering system with the first record number in the same database
designated as "0". This means that a database read and written with the 'C' api 
will have its record numbers begin with "1" while the same database accessed with 
perl-BerkeleyDB will have record numbers starting with "0".

=head1 TOOLS

There are three other modules that come with this bundle. Briefly their
purpose is as follows:

=over 4

=item * IPTables::IPv4::DBTarpit::Tools

The Tools module provides an easy interface to the database used by the DBTarpit
daemon. Build applications that access the database(s) using this module.

=item * IPTables::IPv4::DBTarpit::Config

The Config module reports the configuration of the DBTarpit bundle at
installation time for use in modules that need to know where various
components may be either at build or run time.

=item * IPTables::IPv4::DBTarpit::Inst

Inst is a small module that provide a set of methods to carry on a dialog
with the installer of a module and generate a config file and Makefile text
based on the config file. See B<inst/dialog.pl> in this package (it is a bit
atypical) or B<inst/dialog.pl> for any of the SpamCannibal modules
(typical).

=back

For detailed information, please read the man pages for these modules.

=head1 APPLICATIONS

... aahhh! now you come to the fun part.

See L<MAIL::SpamCannibal>

Used with C<dbtarpit>, it "eats" the spammer for lunch. In less graphic
terms, SpamCannibal is a set of tools that helps you identify the
originating mail server for the spam message and add the offender's IP
address to the tarpit. There are "trolling" tools to allow you to check the
DNSBL databases for hits against C<dbtarpit's> archive database and a host of
other goodies to help make life difficult for spammers.

I'm sure you can think of many other applications, but this one is on the
top of my list.

=head1 ACKNOWLEDGEMENTS

There are many contributors to this project. Major code snippets came from
the work of:

	ipt_TARPIT.c 	by Aaron Hopkins <tools@die.net>
  http://www.netfilter.org/documentation/pomlist/pom-summary.html#extra

	LaBrea		by Tom Liston <tliston@premmag.com>
  http://www.hackbusters.net/LaBrea/

  and... and interesting email from Cody Hatch <cody@halosec.com>
	about using a tarpit to trap spammers.
  http://mail.nl.linux.org/offtopic/2002-10/msg00000.html

=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

=head1 COPYRIGHT AND LICENCE

  Copyright 2003, Michael Robinton <michael@bizsystems.com>
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=head1 SEE ALSO

L<IPTables::IPv4::DBTarpit::Tools>,
L<IPTables::IPv4::DBTarpit::Inst>,
L<IPTables::IPv4::DBTarpit::Config>,
L<libdbtarpit>,
L<dbtarpit> 
and for manual db administration, the utility B<bdbutil.pl>

=cut

# end C comments */
