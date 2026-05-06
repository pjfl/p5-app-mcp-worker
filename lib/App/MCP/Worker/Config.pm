package App::MCP::Worker::Config;

use Class::Usul::Cmd::Constants qw( FALSE TRUE );
use File::DataClass::Types      qw( Directory Path HashRef Str );
use Class::Usul::Cmd::Util      qw( distname );
use File::DataClass::IO         qw( io );
use Moo;

has 'appclass' => is => 'ro', isa => Str, required => TRUE;

has 'logfile' =>
   is      => 'lazy',
   isa     => Path,
   default => sub {
      my $self = shift;
      my $dist = lc distname $self->appclass;

      return $self->home->catfile('.' . $dist . '-worker.log');
   };

has 'home' => is => 'ro', isa => Directory, default => sub { io '.' };

has 'prefix' => is => 'ro', isa => Str, default => 'mcp';

has 'tempdir' => is => 'lazy', default => sub { shift->home };

has 'uri_template' =>
   is      => 'ro',
   isa     => HashRef,
   default => sub {
      return {
         authenticate  => '/mcp/api/user/%s/authenticate',
         event         => '/mcp/api/run/%s/create_event',
         exchange_keys => '/mcp/api/user/%s/exchange_keys',
         job           => '/mcp/api/session/%s/create_job',
      }
   };

has 'vardir' =>
   is      => 'lazy',
   isa     => Directory,
   default => sub {
      my $self = shift;
      my $dir  = $self->home->catdir('var');

      return $dir->exists ? $dir : $self->home;
   };

use namespace::autoclean;

1;
