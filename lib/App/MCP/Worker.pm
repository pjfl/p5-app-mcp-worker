package App::MCP::Worker;

use 5.010001;
use namespace::autoclean;
use version; our $VERSION = qv( sprintf '0.2.%d', q$Rev: 22 $ =~ /\d+/gmx );

use Class::Usul::Constants  qw( EXCEPTION_CLASS FALSE OK SPC TRUE );
use Class::Usul::Crypt      qw( encrypt );
use Class::Usul::Functions  qw( bson64id pad throw );
use Data::Record;
use English                 qw( -no_match_vars );
use File::DataClass::Types  qw( ArrayRef Directory HashRef NonEmptySimpleStr
                                NonZeroPositiveInt SimpleStr Str );
use Regexp::Common;
use Try::Tiny;
use Type::Utils             qw( as coerce from subtype via );
use Unexpected::Functions   qw( Unspecified );
use Moo;
use Class::Usul::Options;

extends 'Class::Usul::Programs';
with    'App::MCP::Worker::Role::UserPassword';
with    'App::MCP::Worker::Role::ClientAuth';

my $ShellCmd = subtype as ArrayRef;

coerce $ShellCmd, from Str, via {
   my $split_on_space = { split => SPC, unless => $RE{quoted} };

   return [ Data::Record->new( $split_on_space )->records( $_ ) ];
};

my $ServerList = subtype as ArrayRef;

coerce $ServerList, from Str, via { [ split m{ [,] }mx, $_ ] };

# Public attributes
option 'job'       => is => 'ro',   isa => HashRef,
   documentation   => 'Keys and values of a job definition in JSON format',
   default         => sub { {} },   json => TRUE, short => 'j';

option 'port'      => is => 'ro',   isa => NonZeroPositiveInt,
   documentation   => 'Port number for the remote servers. Defaults to 2012',
   default         => 2012,         format => 'i', short => 'p';

option 'protocol'  => is => 'ro',   isa => NonEmptySimpleStr,
   documentation   => 'Which network protocol to use. Defaults to http',
   default         => 'http',       format => 's', short => 'P';

option 'servers'   => is => 'ro',   isa => $ServerList, coerce => TRUE,
   documentation   => 'List of servers to send response status to',
   default         => 'localhost',  format => 's', short => 's';

has 'command'      => is => 'lazy', isa => $ShellCmd, coerce => TRUE,
   default         => 'true';

has 'directory'    => is => 'ro',   isa => Directory | SimpleStr;

has 'job_id'       => is => 'ro',   isa => NonZeroPositiveInt, default => $PID;

has 'runid'        => is => 'ro',   isa => NonEmptySimpleStr,
   default         => bson64id;

has 'token'        => is => 'ro',   isa => SimpleStr;

has 'uri_template' => is => 'ro',   isa => HashRef, default => sub { {
   authenticate    => '/api/authenticate/%s',
   event           => '/api/event?runid=%s',
   job             => '/api/job?sessionid=%s', } };

# Private functions
my $_chdir = sub {
   my $dir = shift;

         $dir or throw Unspecified, [ 'directory' ];
   chdir $dir or throw 'Directory [_1] cannot chdir: [_2]', [ $dir, $OS_ERROR ];
   return $dir;
};

# Private methods
my $_send_event = sub {
   my ($self, $transition, $r) = @_;

   my $runid  = $self->runid;
   my $json   = $self->transcoder;
   my $event  = { job_id => $self->job_id, pid        => $PID,
                  runid  => $runid,        transition => $transition, };
   my $prefix = (pad uc $transition, 9, SPC, 'left')."[${runid}]: ";
   my $format = $self->protocol."://%s:".$self->port
                .sprintf $self->uri_template->{event}, $runid;

   $r and $event->{rv} = $r->rv;
   $self->log->debug( $prefix.($r ? 'Rv '.$r->rv : "Pid ${PID}") );
   $event = encrypt $self->token, $json->encode( $event );

   for my $server (@{ $self->servers }) {
      try {
         my $uri     = sprintf $format, $server;
         my $res     = $self->post_as_json( $uri, { event => $event } );
         my $message = $res->content->{message};

         $res->is_success
            or throw 'Run [_1] send event failed code [_2]: [_3]',
                     [ $runid, $res->code, $message ];
         $self->log->debug( $prefix.$message );
      }
      catch { $self->log->error( $_ ) };
   }

   return;
};

my $_run_command = sub {
   my $self = shift; $self->$_send_event( 'started' );

   try {
      $self->directory and $_chdir->( $self->directory );

      my $r = $self->run_cmd( $self->command, { expected_rv => 255 } );

      $self->$_send_event( 'finish', $r );
   }
   catch { $self->log->error( $_ ); $self->$_send_event( 'terminate' ) };

   return;
};

# Public methods
sub create_job : method {
   my $self    = shift;
   my $json    = $self->transcoder;
   my $server  = $self->servers->[ 0 ];
   my $plate   = $self->uri_template->{authenticate};
   my $uri     = $self->protocol."://${server}:".$self->port;
   my $sess    = $self->authenticate_session( $uri, { template => $plate } );
   my $sess_id = $sess->{id};
   my $job     = encrypt $sess->{shared_secret}, $json->encode( $self->job );
      $uri    .= sprintf $self->uri_template->{job}, $sess_id;
   my $res     = $self->post_as_json( $uri, { job => $job } );
   my $message = $res->content->{message};

   $res->is_success
      or throw 'Session [_1] create job failed code [_2]: [_3]',
               [ $sess_id, $res->code, $message ];

   $self->info( "SESS[${sess_id}]: ${message}" );
   return OK;
}

sub dispatch {
   my $self = shift;

   my $r = $self->run_cmd( [ sub { $self->$_run_command } ], { async => TRUE });

   return $r->out;
}

sub set_client_password : method {
   $_[ 0 ]->set_user_password( @{ $_[ 0 ]->extra_argv } ); return OK;
}

1;

__END__

=pod

=encoding utf-8

=head1 Name

App::MCP::Worker - Remotely executed worker process

=head1 Version

This documents version v0.2.$Rev: 22 $ of L<App::MCP::Worker>

=head1 Synopsis

   use App::MCP::Worker;

=head1 Description

Remotely executed worker process

=head1 Configuration and Environment

Defines the following attributes;

=over 3

=item C<command>

=item C<directory>

=item C<job_id>

=item C<port>

=item C<protocol>

=item C<runid>

=item C<servers>

=item C<token>

=item C<uri_template>

=back

=head1 Subroutines/Methods

=head2 C<create_job> - Creates a new job on an MCP job scheduler

=head2 C<dispatch>

=head2 C<set_client_password> - Stores the clients API password in a local file

=head1 Diagnostics

None

=head1 Dependencies

You need to install the GNU MP library (C<libgmp3-dev>) which is required by
L<Crypt::SRP> to install this distribution

=over 3

=item L<namespace::autoclean>

=item L<Authen::HTTP::Signature>

=item L<Class::Usul>

=item L<Crypt::SRP>

=item L<Data::Record>

=item L<File::DataClass>

=item L<JSON::MaybeXS>

=item L<LWP::UserAgent>

=item L<Moo>

=item L<Regexp::Common>

=item L<Try::Tiny>

=item L<Type::Tiny>

=item L<Unexpected>

=back

=head1 Incompatibilities

There are no known incompatibilities in this module

=head1 Bugs and Limitations

There are no known bugs in this module.
Please report problems to the address below.
Patches are welcome

=head1 Acknowledgements

Larry Wall - For the Perl programming language

=head1 Author

Peter Flanigan, C<< <pjfl@cpan.org> >>

=head1 License and Copyright

Copyright (c) 2014 Peter Flanigan. All rights reserved

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. See L<perlartistic>

This program is distributed in the hope that it will be useful,
but WITHOUT WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE

=cut

# Local Variables:
# mode: perl
# tab-width: 3
# End:
