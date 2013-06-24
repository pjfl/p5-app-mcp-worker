# @(#)$Ident: Build.PL 2013-06-24 16:11 pjf ;

use strict;
use warnings;
use inc::Bob; # Module::Build subclass
use version; our $VERSION = qv( sprintf '0.1.%d', q$Rev: 4 $ =~ /\d+/gmx );

Bob->new( {
   module    => q(App::MCP::Worker),
   home_page => q(http://www.roxsoft.co.uk),
   requires  => {
      'perl'             => 5.01,
      'namespace::sweep' => 0.006,
      'Class::Usul'      => q(0.21.0),
      'File::DataClass'  => q(0.20.0),
      'HTTP::Message'    => 6.06,
      'LWP::UserAgent'   => 6.04,
      'Moo'              => 1.002000,
      'MooX::Options'    => 3.83,
      'TryCatch'         => 1.003000,
      'Type::Tiny'       => 0.008, },
   recommends            => {
      'App::cpanminus'   => 1.4004 },
   configure_requires    => {
      'version'          => 0.88,
      'Module::Build'    => 0.4004, },
   build_requires        => {
      'version'          => 0.88,
      'Module::Build'    => 0.4004, },
} )->create_build_script; # Goal!

# Local Variables:
# eval: (load-project-state "app-mcp-worker")
# mode: perl
# tab-title: Worker
# tab-width: 3
# End:
