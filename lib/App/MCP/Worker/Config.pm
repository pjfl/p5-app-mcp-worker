package App::MCP::Worker::Config;

use File::DataClass::IO qw( io );
use Moo;

has 'appclass' => is => 'ro', default => 'App::MCP::Worker';

has 'logfile' =>
   is      => 'lazy',
   default => sub { shift->my_home->catfile('.app-mcp-worker.log') };

has 'my_home' => is => 'ro', default => sub { io '.' };

has 'prefix' => is => 'ro', default => 'mcp';

use namespace::autoclean;

1;
