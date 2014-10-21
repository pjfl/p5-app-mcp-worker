use strict;
use warnings;
use File::Spec::Functions qw( catdir updir );
use FindBin               qw( $Bin );
use lib               catdir( $Bin, updir, 'lib' );

use Test::More;
use Test::Requires { version => 0.88 };
use Module::Build;

my $notes = {}; my $perl_ver;

BEGIN {
   my $builder = eval { Module::Build->current };
      $builder and $notes = $builder->notes;
      $perl_ver = $notes->{min_perl_version} || 5.008;
}

use Test::Requires "${perl_ver}";

use_ok 'App::MCP::Worker';

my $job = { condition => 'finished( remote1 )', command   => 'sleep 2',
            host      => 'head',                name      => 'remote2',
            type      => 'job',                 user      => 'mcp', };

is App::MCP::Worker->new_with_options
   ( appclass => 'App::MCP', debug => 1, job => $job,
     method   => 'create_job', noask => 1 )->run, 0, 'Creates job';

done_testing;

# Local Variables:
# mode: perl
# tab-width: 3
# End:
# vim: expandtab shiftwidth=3:
