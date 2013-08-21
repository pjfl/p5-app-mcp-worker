# @(#)$Ident: 10test_script.t 2013-08-21 23:18 pjf ;

use strict;
use warnings;
use version; our $VERSION = qv( sprintf '0.2.%d', q$Rev: 1 $ =~ /\d+/gmx );
use File::Spec::Functions   qw( catdir updir );
use FindBin                 qw( $Bin );
use lib                 catdir( $Bin, updir, 'lib' );

use Module::Build;
use Test::More;

my $notes = {}; my $perl_ver;

BEGIN {
   my $builder = eval { Module::Build->current };
      $builder and $notes = $builder->notes;
      $perl_ver = $notes->{min_perl_version} || 5.008;
}

use_ok 'App::MCP::Worker';

done_testing;

# Local Variables:
# mode: perl
# tab-width: 3
# End:
