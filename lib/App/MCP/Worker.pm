package App::MCP::Worker;

use 5.010001;
use version; our $VERSION = qv( sprintf '0.2.%d', q$Rev: 25 $ =~ /\d+/gmx );

use Class::Usul::Cmd::Constants  qw( EXCEPTION_CLASS FALSE OK QUOTED_RE SPC
                                     TRUE );
use File::DataClass::Types       qw( ArrayRef Directory HashRef
                                     NonEmptySimpleStr NonZeroPositiveInt
                                     SimpleStr Str );
use Web::ComposableRequest::Util qw( bson64id );
use Class::Usul::Cmd::Util       qw( encrypt pad );
use English                      qw( -no_match_vars );
use Type::Utils                  qw( as coerce from subtype via );
use Unexpected::Functions        qw( throw Unspecified );
use App::MCP::Worker::Config;
use Data::Record;
use Try::Tiny;
use Moo;
use Class::Usul::Cmd::Options;

extends 'Class::Usul::Cmd';
with    'App::MCP::Worker::Role::UserPassword';
with    'App::MCP::Worker::Role::ClientAuth';

my $ShellCmd = subtype as ArrayRef;

coerce $ShellCmd, from Str, via {
   my $split_on_space = { split => SPC, unless => QUOTED_RE };

   return [ Data::Record->new($split_on_space)->records($_) ];
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

has 'uri_template' => is => 'ro',   isa => HashRef, default => sub {
   return {
      authenticate  => '/api/worker/%s/authenticate',
      event         => '/api/worker/%s/create_event',
      exchange_keys => '/api/worker/%s/exchange_keys',
      job           => '/api/worker/%s/create_job',
   }
};

around 'BUILDARGS' => sub {
   my ($orig, $self, @args) = @_;

   my $attr = $orig->($self, @args);

   $attr->{config} //= App::MCP::Worker::Config->new();

   return $attr;
};

# Public methods
sub create_job : method {
   my $self    = shift;
   my $json    = $self->transcoder;
   my $server  = $self->servers->[0];
   my $tplate  = $self->uri_template;
   my $uri     = $self->protocol."://${server}:" . $self->port;
   my $sess    = $self->authenticate_session($uri, { template => $tplate });
   my $sess_id = $sess->{id};
   my $job     = encrypt $sess->{shared_secret}, $json->encode($self->job);
      $uri    .= sprintf $self->uri_template->{job}, $sess_id;
   my $res     = $self->post_as_json($uri, { job => $job });
   my $message = $res->content->{message};

   throw 'Session [_1] create job failed code [_2]: [_3]',
      [ $sess_id, $res->code, $message ] unless $res->is_success;

   $self->info("SESS[${sess_id}]: ${message}");
   return OK;
}

sub dispatch {
   my $self = shift;

   my $r = $self->run_cmd([ sub { $self->_run_command } ], { async => TRUE });

   return $r->out;
}

sub set_client_password : method {
   my $self = shift;

   $self->set_user_password(@{$self->extra_argv});
   return OK;
}

# Private methods
sub _send_event {
   my ($self, $transition, $r) = @_;

   my $runid  = $self->runid;
   my $json   = $self->transcoder;
   my $event  = {
      job_id     => $self->job_id,
      pid        => $PID,
      runid      => $runid,
      transition => $transition,
   };
   my $prefix = (pad uc $transition, 9, SPC, 'left') . "[${runid}]: ";
   my $format = $self->protocol . "://%s:" . $self->port
              . sprintf $self->uri_template->{event}, $runid;

   $event->{rv} = $r->rv if $r;

   $self->log->debug($prefix . ($r ? 'Rv '.$r->rv : "Pid ${PID}"));
   $event = encrypt $self->token, $json->encode($event);

   for my $server (@{$self->servers}) {
      try {
         my $uri     = sprintf $format, $server;
         my $res     = $self->post_as_json($uri, { event => $event });
         my $message = $res->content->{message};

         throw 'Run [_1] send event failed code [_2]: [_3]',
            [ $runid, $res->code, $message ] unless $res->is_success;

         $self->log->debug($prefix . $message);
      }
      catch { $self->log->error($_) };
   }

   return;
}

sub _run_command {
   my $self = shift;

   $self->_send_event('started');

   try {
      _chdir($self->directory) if $self->directory;

      my $r = $self->run_cmd($self->command, { expected_rv => 255 });

      $self->_send_event('finish', $r);
   }
   catch {
      $self->log->error($_);
      $self->_send_event('terminate');
   };

   return;
}

# Private functions
sub _chdir {
   my $dir = shift;

   throw Unspecified, ['directory'] unless $dir;
   throw 'Directory [_1] cannot chdir: [_2]', [$dir, $OS_ERROR]
      unless chdir $dir;

   return $dir;
}

use namespace::autoclean;

1;

__END__

=pod

=encoding utf-8

=head1 Name

App::MCP::Worker - Remotely executed worker process

=head1 Version

This documents version v0.2.$Rev: 25 $ of L<App::MCP::Worker>

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

=item L<Class::Usul::Cmd>

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
