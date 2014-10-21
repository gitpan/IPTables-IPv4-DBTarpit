# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.
# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..7\n"; }
END {print "not ok 1\n" unless $loaded;}

use Cwd;
use IPTables::IPv4::DBTarpit::Tools qw(
	$DBTP_ERROR
	db_strerror
);

$TPACKAGE = 'IPTables::IPv4::DBTarpit::Tools';
$loaded = 1;
print "ok 1\n";
######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

$test = 2;

umask 007;
foreach my $dir (qw(tmp tmp.dbhome tmp.bogus)) {
  if (-d $dir) {         # clean up previous test runs
    opendir(T,$dir);
    @_ = grep(!/^\./, readdir(T));
    closedir T;
    foreach(@_) {
      unlink "$dir/$_";
    }
    rmdir $dir or die "COULD NOT REMOVE $dir DIRECTORY\n";
  }
  unlink $dir if -e $dir;	# remove files of this name as well
}

sub ok {
  print "ok $test\n";
  ++$test;
}

sub next_sec {
  my ($then) = @_;
  $then = time unless $then;
  my $now;
# wait for epoch
  do { select(undef,undef,undef,0.1); $now = time }
        while ( $then >= $now );
  $now;
}

### database loader
# takes one test cycle
#
# input:	tool,db,\%hash
#
sub dbinsert {
  my($tool,$db,$hp) = @_;
  my $err;
  while(my($k,$v) = each %$hp) {
    if ($err = $tool->put($db,$k,$v,)) {
      print "insert failure, database '$db'\nnot ";
      last;
    }
  }
  &ok;
}

## database checker
# takes 3 test cycles
#
# input:	tool,db,\%hash
#
sub dbcheck {
  my($tool,$db,$hp) = @_;
  my($err,%copy);
# dump database to %copy
  my $cursor = 1;
  while(@_ = $tool->getrecno($db,$cursor++)) {
    my ($k,$v) = @_;
    $copy{$k} = $v;
  }
  print "failed to dump '$db'\nnot "
	unless keys %copy;
  &ok;
# check keys
  my $x = keys %$hp;
  my $y = keys %copy;
  print "bad key count ans=$x, db=$y\nnot "
	if $x != $y;
  &ok;
# check data content
  foreach(keys %copy) {
    if ($hp->{$_} !~ /^$copy{$_}$/) {
      print "data mismatch in '$db'\nnot ";
      last;
    }
  }
  &ok;
}

my $localdir = cwd();
my $dbhome = "$localdir/tmp.dbhome";

my %new = (
	dbfile	=> ['tarpit'],
	dbhome	=> $dbhome,
);

mkdir 'tmp';
	
## test 2 -  establish DB connections
my $tool = eval {
	new $TPACKAGE(%new);
};
print "failed to open db\nnot " if $@;
&ok;

###
### preliminary's finished
###

## test 3

my $time = &next_sec();
my %tarpit = (
	one	=> $time -20,
	two	=> $time -10,
	three	=> $time -5,
	four	=> $time -1,
	five	=> $time,
);

dbinsert($tool,'tarpit',\%tarpit);

## test 4	check for clear error
print "unexpected error response: ", db_strerror($DBTP_ERROR), "\nnot "
	if $DBTP_ERROR;
&ok;

## test 5	check for no answer
my $answer = $tool->get('tarpit','notakey');
print "unexpected response: $answer\nnot "
	if $answer;
&ok;

## test 6	check forced error
print "expected error not found\nnot "
	unless $DBTP_ERROR;
&ok;

print "got unknown error response: $_
exp: DB_NOTFOUND: (+ text)\nnot "
	unless ($_ = db_strerror($DBTP_ERROR));
&ok;

$tool->closedb();
