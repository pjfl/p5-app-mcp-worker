# @(#)$Id$

use strict;
use warnings;
use inc::Bob; # Module::Build subclass
use version; our $VERSION = qv( sprintf '0.1.%d', q$Rev: 1 $ =~ /\d+/gmx );

Bob->new( {
   module     => q(App::MCP::Worker),
   home_page  => q(http://www.roxsoft.co.uk),
   requires   => {
      'perl'             => 5.010,
      'version'          => 0.77,
      'Class::Usul'      => q(0.9.0),
      'File::DataClass'  => q(0.12.0),
   },
   recommends            => {
      'App::cpanminus'   => 1.4004 },
   configure_requires    => {
      'version'          => 0.77,
      'Module::Build'    => 0.38, },
   build_requires        => {
      'Exception::Class' => 1.23,
      'Test::More'       => 0.74, },
} )->create_build_script; # Goal!

# Local Variables:
# tab-title: App::MCP::Worker
# eval: (load-project-state "app-mcp-worker")
# mode: perl
# tab-width: 3
# End:
