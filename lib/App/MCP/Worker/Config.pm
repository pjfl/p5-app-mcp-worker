package App::MCP::Worker::Config;

use File::DataClass::IO qw( io );
use Moo;

has 'appclass' => is => 'ro', required => 1;

has 'logfile' =>
   is      => 'lazy',
   default => sub { shift->home->catfile('.app-mcp-worker.log') };

has 'home' => is => 'ro', default => sub { io '.' };

has 'prefix' => is => 'ro', default => 'mcp';

use namespace::autoclean;

1;
