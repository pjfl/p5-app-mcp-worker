package App::MCP::Worker;

use 5.010001;
use namespace::sweep;
use version; our $VERSION = qv( sprintf '0.2.%d', q$Rev: 5 $ =~ /\d+/gmx );

use Moo;
use Authen::HTTP::Signature;
use Class::Usul::Constants;
use Class::Usul::Crypt         qw( decrypt encrypt );
use Class::Usul::Crypt::Util   qw( dh_base dh_mod );
use Class::Usul::Functions     qw( bson64id class2appdir exception pad throw );
use Class::Usul::Options;
use Convert::SSH2;
use Crypt::DH;
use Cwd                        qw( getcwd );
use Data::Record;
use Digest                     qw( );
use Crypt::Eksblowfish::Bcrypt qw( bcrypt );
use English                    qw( -no_match_vars );
use File::DataClass::Types     qw( ArrayRef Directory HashRef LoadableClass
                                   NonEmptySimpleStr NonZeroPositiveInt
                                   Object SimpleStr Str );
use HTTP::Status               qw( HTTP_EXPECTATION_FAILED HTTP_UNAUTHORIZED );
use HTTP::Request::Common      qw( POST );
use LWP::UserAgent;
use JSON                       qw( );
use Regexp::Common;
use Sys::Hostname;
use TryCatch;
use Type::Utils                qw( as coerce from subtype via );
use Unexpected::Functions      qw( Unspecified );

extends q(Class::Usul::Programs);
with    q(App::MCP::Worker::ClientAuth);

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

has 'command'      => is => 'lazy', isa => $ShellCmd, default => 'true',
   coerce          => $ShellCmd->coercion;

has 'directory'    => is => 'ro',   isa => Directory | SimpleStr;

has 'job_id'       => is => 'ro',   isa => NonZeroPositiveInt, default => $PID;

has 'runid'        => is => 'ro',   isa => NonEmptySimpleStr,
   default         => bson64id;

has 'token'        => is => 'ro',   isa => SimpleStr;

has 'uri_template' => is => 'ro',   isa => HashRef, default => sub { {
   authenticate    => '/api/authenticate/%s',
   event           => '/api/event/%s',
   job             => '/api/job/%s', } };

# Private attributes
has '_transcoder'  => is => 'lazy', isa => Object,
   builder         => sub { JSON->new }, reader => 'transcoder';

has '_user_agent'  => is => 'lazy', isa => Object,
   builder         => sub { LWP::UserAgent->new }, reader => 'user_agent';

# Public methods
sub create_job : method {
   my $self    = shift;
   my $json    = $self->transcoder;
   my $server  = $self->servers->[ 0 ];
   my $uri     = $self->protocol."://${server}:".$self->port;
   my $sess    = $self->_authenticate_session( $uri );
   my $sess_id = $sess->{id};
      $uri    .= sprintf $self->uri_template->{job}, $sess_id;
   my $job     = encrypt $sess->{token}, $json->encode( $self->job );
   my $res     = $self->_post_as_json( $uri, { job => $job } );
   my $message = $json->decode( $res->content )->{message};

   $res->is_success
      or throw error => 'Session [_1] create job failed code [_2]: [_3]',
               args  => [ $sess_id, $res->code, $message ];

   $self->info( "SESS[${sess_id}]: ${message}" );
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
sub _authenticate_session {
   my ($self, $uri, $opts) = @_; $opts //= {};

   my $user_name = $opts->{user_name} || $self->user_name;
   my $password  = $opts->{password } || $self->get_user_password( $user_name );
   my $dh        = Crypt::DH->new( g => dh_base, p => dh_mod );
   my $template  = $self->uri_template->{authenticate};

   $dh->generate_keys; $uri .= sprintf $template, $user_name;

   my $pub_key   = NUL.$dh->pub_key;
   my $res       = $self->_post_as_json( $uri, { public_key => $pub_key } );
   my $priv_key  = $self->_decode_priv_key( $dh, $user_name, $password, $res );
   my $token     = encrypt $priv_key, $password;

   $res = $self->_post_as_json( $uri, { authenticate => $token } );

   return $self->_decode_session( $priv_key, $user_name, $res );
}

sub _decode_priv_key {
   my ($self, $dh, $user_name, $password, $res) = @_;

   my $content = $self->transcoder->decode( $res->content );

   $res->is_success
      or throw error => 'User [_1] authentication failure code [_2]: [_3]',
               args  => [ $user_name, $res->code, $content->{message} ];

   my $hash_val = bcrypt( $password, $content->{salt} );
   my $pub_key  = decrypt $hash_val, $content->{public_key};

   return $dh->compute_secret( $pub_key );
}

sub _decode_session {
   my ($self, $priv_key, $user_name, $res) = @_;

   my $json = $self->transcoder; my $content = $json->decode( $res->content );

   $res->is_success
      or throw error => 'User [_1] authentication failure code [_2]: [_3]',
               args  => [ $user_name, $res->code, $content->{message} ];

   my $session; my $token = $content->{token};

   try        { $session = $json->decode( decrypt $priv_key, $token ) }
   catch ($e) {
      $self->log->debug( $e );
      throw error => 'User [_1] authentication failure: Incorrect shared key',
            args  => [ $user_name ];
   }

   $self->log->debug( "User ${user_name} Session-Id ".$session->{id} );

   return $session;
}

sub _post_as_json {
   my ($self, $uri, $content) = @_; my $key = $self->_read_private_key;

   $content = $self->transcoder->encode( $content );

   my $digest = Digest->new( 'SHA-512' ); $digest->add( $content );
   my $req    = POST $uri, 'Content-SHA512' => $digest->hexdigest,
                           'Content-Type'   => 'application/json',
                           'Content'        => $content;
   # TODO: Why doest hmac-sha512 not work?
   my $signer = Authen::HTTP::Signature->new
      ( headers => [ 'Content-SHA512' ], key => $key, key_id => hostname, );

   return $self->user_agent->request( $signer->sign( $req ) );
}

sub _read_private_key {
   my ($self, $key_id) = @_; state $cache //= {};

   $key_id //= class2appdir $self->config->appclass;

   my $key     = $cache->{ $key_id }; $key and return $key;
   my $ssh_dir = $self->config->my_home->catdir( '.ssh' );

   return $cache->{ $key_id } = $ssh_dir->catfile( "${key_id}.priv" )->all;
}

sub _run_command {
   my $self = shift; my $r; $self->_send_event( 'started' );

   try {
      $self->directory and __chdir( $self->directory );
      $r = $self->run_cmd( $self->command );
   }
   catch ($e) { $self->_send_event( 'terminate' ); return }

   $self->_send_event( 'finish', $r );
   return;
}

sub _send_event {
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
         my $res     = $self->_post_as_json( $uri, { event => $event } );
         my $message = $json->decode( $res->content )->{message};

         $res->is_success
            or throw error => 'Run [_1] send event failed code [_2]: [_3]',
                     args  => [ $runid, $res->code, $message ];
         $self->log->debug( $prefix.$message );
      }
      catch ($e) { $self->log->error( $e ) }
   }

   return;
}

# Private functions
sub __chdir {
   my $dir = shift;

         $dir or throw class => Unspecified, args => [ 'directory' ];
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

This documents version v0.2.$Rev: 5 $ of L<App::MCP::Worker>

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

=item C<uri_template>

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
