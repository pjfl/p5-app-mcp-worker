use t::boilerplate;

use Test::More;

use_ok 'App::MCP::Worker';

my $job = { condition => 'finished( remote1 )', command   => 'sleep 2',
            host      => 'head',                name      => 'remote2',
            type      => 'job',                 user      => 'mcp', };

is App::MCP::Worker->new_with_options
   ( appclass => 'App::MCP::Worker',
     config   => { prefix => 'mcp' },
     debug    => 1,
     job      => $job,
     method   => 'create_job',
     noask    => 1 )->run, 0, 'Creates job';

done_testing;

# Local Variables:
# mode: perl
# tab-width: 3
# End:
# vim: expandtab shiftwidth=3:
