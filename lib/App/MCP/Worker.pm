# @(#)$Ident: Worker.pm 2013-10-31 23:06 pjf ;

package App::MCP::Worker;

use 5.010001;
use namespace::sweep;
use version;    our $VERSION = qv( sprintf '0.2.%d', q$Rev: 3 $ =~ /\d+/gmx );

use Class::Usul::Constants;
use Class::Usul::Crypt         qw( decrypt encrypt );
use Class::Usul::Functions     qw( bson64id exception pad throw );
use Crypt::Eksblowfish::Bcrypt qw( bcrypt );
use Cwd                        qw( getcwd );
use English                    qw( -no_match_vars );
use File::DataClass::Types     qw( ArrayRef Directory HashRef NonEmptySimpleStr
                                   NonZeroPositiveInt Object SimpleStr Str );
use HTTP::Request::Common      qw( POST );
use LWP::UserAgent;
use Moo;
use MooX::Options;
use JSON                       qw( );
use TryCatch;
use Type::Utils                qw( as coerce from subtype via );

extends q(Class::Usul::Programs);
with    q(Class::Usul::TraitFor::UntaintedGetopts);
with    q(App::MCP::Worker::ClientAuth);

my $ServerList = subtype as ArrayRef;

coerce $ServerList, from Str, via { [ split SPC, $_ ] };

option 'job'       => is => 'ro',   isa => HashRef,
   documentation   => 'Keys and values of a job definition in JSON format',
   default         => sub { {} }, json => TRUE, short => 'j';

option 'port'      => is => 'ro',   isa => NonZeroPositiveInt, default => 2012,
   documentation   => 'Port number for the remote servers. Defaults to 2012',
   format          => 'i', short => 'p';

option 'protocol'  => is => 'ro',   isa => NonEmptySimpleStr, default => 'http',
   documentation   => 'Which network protocol to use. Defaults to http',
   format          => 's', short => 'P';

option 'servers'   => is => 'ro',   isa => $ServerList, default => 'localhost',
   documentation   => 'List of servers to send request to',
   coerce          => $ServerList->coercion, format => 's', short => 's';

option 'user_name' => is => 'ro',   isa => NonEmptySimpleStr,
   documentation   => 'Name in the user table and .mcprc file',
   default         => 'unknown', format => 's', short => 'u';

has 'command'      => is => 'ro',   isa => NonEmptySimpleStr, default => 'true';

has 'directory'    => is => 'ro',   isa => Directory | SimpleStr;

has 'job_id'       => is => 'ro',   isa => NonZeroPositiveInt, default => $PID;

has 'runid'        => is => 'ro',   isa => NonEmptySimpleStr,
   default         => bson64id;

has 'token'        => is => 'ro',   isa => SimpleStr;

has 'ev_uri_fmt'   => is => 'ro',   isa => NonEmptySimpleStr,
   default         => 'api/event/%s';

has 'job_uri_fmt'  => is => 'ro',   isa => NonEmptySimpleStr,
   default         => 'api/job/%s';

has 'sess_uri_fmt' => is => 'ro',   isa => NonEmptySimpleStr,
   default         => 'api/session/%s';

has '_transcoder'  => is => 'lazy', isa => Object,
   builder         => sub { JSON->new }, reader => 'transcoder';

has '_user_agent'  => is => 'lazy', isa => Object,
   builder         => sub { LWP::UserAgent->new }, reader => 'user_agent';

# Public methods
sub create_job : method {
   my $self    = shift;
   my $json    = $self->transcoder;
   my $server  = $self->servers->[ 0 ];
   my $uri     = $self->protocol."://${server}:".$self->port.'/';
   my $sess    = $self->_get_authenticated_session( $uri ) or return FAILED;
   my $sess_id = $sess->{id};
      $uri    .= sprintf $self->job_uri_fmt, $sess_id;
   my $job     = encrypt $sess->{token}, $json->encode( $self->job );
   my $res     = $self->_post_as_json( $uri, { job => $job } );
   my $content = $json->decode( $res->content );
   my $message = " JOB[${sess_id}]: ".$res->code.SPC.$content->{message};

   unless ($res->is_success) { $self->error( $message ); return FAILED }

   $self->info( $message );
   return OK;
}

sub dispatch {
   my $self = shift;

   my $r = $self->run_cmd( [ sub { $self->_run_command } ], { async => TRUE } );

   return $r->out;
}

sub set_client_password : method {
   $_[ 0 ]->set_user_password( @{ $_[ 0 ]->extra_argv } ); return OK;
}

# Private methods
sub _get_authenticated_session {
   my ($self, $uri, $opts) = @_; $opts //= {};

   my $json      = $self->transcoder;
   my $user_name = $opts->{user_name} || $self->user_name;
      $uri      .= sprintf $self->sess_uri_fmt, $user_name;
   my $res       = $self->_post_as_json( $uri, {} );
   my $content   = $json->decode( $res->content );

   unless ($res->is_success) {
      $self->error( $res->code == 404 ? $content->{message} : $res->message );
      return FALSE;
   }

   my $password  = $opts->{password} || $self->get_user_password( $user_name );
   my $key       = bcrypt( $password, $content->{salt} );
   my $session;

   try        { $session = $json->decode( decrypt $key, $content->{token} ) }
   catch ($e) {
      my $message = 'User [_1] authentication failure';

      $self->error( exception error => $message, args  => [ $user_name ] );
      return FALSE;
   }

   $self->debug and $self->log->debug
      ( $res->code." User ${user_name} Session-Id ".$session->{id} );
   return $session;
}

sub _post_as_json {
   my ($self, $uri, $content) = @_; my $ua = $self->user_agent;

   return $ua->request( POST $uri, 'Content-Type' => 'application/json',
                        content => $self->transcoder->encode( $content ) );
}

sub _run_command {
   my $self = shift; my $r; $self->_send_event( 'started' );

   try {
      $self->directory and __chdir( $self->directory );
      $r = $self->run_cmd( [ split SPC, $self->command ] );
   }
   catch ($e) { $self->_send_event( 'terminate' ); return }

   $self->_send_event( 'finish', $r );
   return;
};

sub _send_event {
   my ($self, $transition, $r) = @_;

   my $runid   = $self->runid;
   my $json    = $self->transcoder;
   my $event   = { job_id => $self->job_id, pid        => $PID,
                   runid  => $runid,        transition => $transition, };
   my $prefix  = (pad uc $transition, 9, SPC, 'left')."[${runid}]: ";
   my $message = $prefix.($r ? 'Rv '.$r->rv : "Pid ${PID}");

   $r and $event->{rv} = $r->rv;
   $self->debug and $self->log->debug( $message );
   $event = encrypt $self->token, $json->encode( $event );

   for my $server (@{ $self->servers }) {
      my $uri     = $self->protocol."://${server}:".$self->port.'/';
         $uri    .= sprintf $self->ev_uri_fmt, $runid;
      my $res     = $self->_post_as_json( $uri, { event => $event } );
      my $content = $json->decode( $res->content );
      my $message = $prefix.$res->code.SPC.$content->{message};

      unless ($res->is_success) { $self->log->error( $message ) }
      else { $self->debug and $self->log->debug( $message ) }
   }

   return;
}

# Private functions
sub __chdir {
   my $dir = shift; $dir or throw 'Directory not specified in chdir';

   chdir $dir or throw error => 'Directory [_1] cannot chdir: [_2]',
                        args => [ $dir, $OS_ERROR ];
   return $dir;
}

1;

__END__

=pod

=head1 Name

App::MCP::Worker - Remotely executed worker process

=head1 Version

This documents version v0.2.$Rev: 3 $

=head1 Synopsis

   use App::MCP::Worker;
   # Brief but working code examples

=head1 Description

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

=item C<uri_format>

=back

=head1 Subroutines/Methods

=head2 create_job - Creates a new job on an MCP job scheduler

=head1 Diagnostics

=head1 Dependencies

=over 3

=item L<Class::Usul>

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

Peter Flanigan, C<< <Support at RoxSoft dot co dot uk> >>

=head1 License and Copyright

Copyright (c) 2013 Peter Flanigan. All rights reserved

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
