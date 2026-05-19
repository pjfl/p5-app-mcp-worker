package App::MCP::Worker;

use 5.010001;
use version; our $VERSION = qv( sprintf '0.2.%d', q$Rev: 34 $ =~ /\d+/gmx );

use Class::Usul::Cmd::Constants  qw( EXCEPTION_CLASS FAILED FALSE NUL OK
                                     QUOTED_RE SPC TRUE );
use File::DataClass::Types       qw( ArrayRef Directory HashRef
                                     NonEmptySimpleStr NonZeroPositiveInt
                                     Path SimpleStr Str Undef );
use File::DataClass::IO          qw( io );
use Web::ComposableRequest::Util qw( bson64id );
use Class::Usul::Cmd::Util       qw( elapsed encrypt ensure_class_loaded pad );
use English                      qw( -no_match_vars );
use Type::Utils                  qw( as coerce from subtype via );
use Unexpected::Functions        qw( throw Unspecified );
use App::MCP::Worker::Log;
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

=pod

=encoding utf-8

=head1 Name

App::MCP::Worker - Remotely executed worker process

=head1 Version

This documents version v0.2.$Rev: 34 $ of L<App::MCP::Worker>

=head1 Synopsis

   #!/usr/bin/env perl

   use App::MCP::Worker;

   exit App::MCP::Worker->new_with_options()->run;

=head1 Description

Remotely executed worker process

=head1 Configuration and Environment

Defines the following attributes;

=over 3

=item C<job>

Keys and values of a job definition in JSON format. Set from the command line
with C<-j>

=cut

option 'job' =>
   is            => 'ro',
   isa           => HashRef,
   documentation => 'Keys and values of a job definition in JSON format',
   default       => sub { {} },
   json          => TRUE,
   short         => 'j';

=item C<port>

Port number for the remote servers. Defaults to B<2012>. Set from the command
line with C<-p>

=cut

option 'port' =>
   is            => 'ro',
   isa           => NonZeroPositiveInt,
   documentation => 'Port number for the remote servers. Defaults to 2012',
   default       => 2012,
   format        => 'i',
   short         => 'p';

=item C<protocol>

Which network protocol to use. Defaults to B<http>. Set from the command line
with C<-P>

=cut

option 'protocol' =>
   is            => 'ro',
   isa           => NonEmptySimpleStr,
   documentation => 'Which network protocol to use. Defaults to http',
   default       => 'http',
   format        => 's',
   short         => 'P';

=item C<servers>

List of servers to send response status to. Defaults to B<localhost>. Set from
the command line with C<-s>

=cut

option 'servers' =>
   is            => 'ro',
   isa           => $ServerList,
   coerce        => TRUE,
   documentation => 'List of servers to send response status to',
   default       => 'localhost',
   format        => 's',
   short         => 's';

=item C<command>

The command to execute. Coerced from a string. Defaults to B<true>

=cut

has 'command' =>
   is      => 'lazy',
   isa     => $ShellCmd,
   coerce  => TRUE,
   default => 'true';

=item C<directory>

The directory from which to execute the command

=cut

has 'directory' => is => 'ro', isa => Directory | SimpleStr | Undef;

=item C<errfile>

Error output from the command is redirected to this file

=cut

has 'errfile' => is => 'ro', isa => Path | SimpleStr | Undef;

=item C<job_id>

The numeric id of the job record

=cut

has 'job_id' => is => 'ro', isa => NonZeroPositiveInt, default => $PID;

=item C<outfile>

Output from the command is redirected to this file

=cut

has 'outfile' => is => 'ro', isa => Path | SimpleStr | Undef;

=item C<pidfile>

Path to the file in which the job's process id is stored. Contains C<runid>

=cut

has 'pidfile' =>
   is      => 'lazy',
   isa     => Path,
   default => sub {
      my $self = shift;

      return $self->config->rundir->catfile($self->runid . '.pid');
   };

=item C<runid>

Unique string for this run of the command

=cut

has 'runid' => is => 'ro', isa => NonEmptySimpleStr, default => bson64id;

=item C<token>

Used to encrypt the command's returned value

=cut

has 'token' => is => 'ro', isa => SimpleStr;

=back

=head1 Subroutines/Methods

Defines the following methods;

=over 3

=item C<BUILDARGS>

Instantiates an instance of the configuration class which is by default
L<App::MCP::Worker::Config>

=cut

around 'BUILDARGS' => sub {
   my ($orig, $self, @args) = @_;

   my $attr = $orig->($self, @args);
   my $config_class = $attr->{config_class} // 'App::MCP::Worker::Config';

   ensure_class_loaded $config_class;

   my $args = { appclass => __PACKAGE__, %{$attr->{config} // {}} };

   $attr->{config} = $config_class->new($args);

   return $attr;
};

=item C<BUILD>

Instantiates the log object if we do not already have one

=cut

sub BUILD {
   my $self = shift;

   $self->log(App::MCP::Worker::Log->new(builder => $self)) unless $self->log;

   return;
}

=item C<archive_file> - Archives a file

Renames the specified file prefixing it with C<A_>

=cut

sub archive_file : method {
   my $self = shift;

   throw Unspecified, ['option path'] unless exists $self->options->{path};

   my $path = io $self->options->{path};

   $path = $path->absolute($self->config->vardir) unless $path->is_absolute;

   return throw 'File [_1] not found', ["${path}"] unless $path->exists;

   my $archive = $path->parent->catfile('A_' . $path->basename);

   $path->move($archive);
   $self->info('Archived ' . $self->options->{path});
   return OK;
}

=item C<create_job> - Creates a new job on an MCP job scheduler

Posts a new job to the server

=cut

sub create_job : method {
   my $self    = shift;
   my $trans   = $self->transcoder;
   my $server  = $self->servers->[0];
   my $tplate  = $self->config->uri_template;
   my $uri     = $self->protocol . "://${server}:" . $self->port;
   my $sess    = $self->authenticate_session($uri, { template => $tplate });
   my $job     = encrypt $sess->{shared_secret}, $trans->encode($self->job);
   my $sess_id = $sess->{id};
      $uri    .= sprintf $tplate->{job}, $sess_id;
   my $res     = $self->post_as_json($uri, { job => $job });

   throw 'Session [_1] create job failed code [_2]: [_3]',
      [$sess_id, $res->{status}, $res->{reason}] unless $res->{success};

   $self->info($res->{content}->{message});
   return OK;
}

=item C<dispatch>

Execute the specified command in a detached child process

=cut

sub dispatch {
   my $self = shift;

   return $self->_kill_job if $self->command->[0] eq 'kill_job';

   my $options = { detach => TRUE, ignore_zombies => FALSE };
   my $result  = $self->run_cmd([ sub { $self->_run_command } ], $options);

   $self->pidfile->println($result->pid)->flush;

   return $result->out;
}

=item C<set_client_password> - Stores the clients API password in a local file

Encrypts the password before storing

=cut

sub set_client_password : method {
   my $self = shift;

   $self->set_user_password(@{$self->extra_argv});
   return OK;
}

=item C<wait_for_awhile> - Waits for some time then finishes

This is a dummy method for testing purposes

=cut

sub wait_for_awhile : method {
   my $self     = shift;
   my $lifetime = $self->next_argv // 10;
   my $rv       = $self->next_argv ? FAILED : OK;

   sleep $lifetime;
   $self->info("Waited for ${lifetime} seconds");
   return $rv;
}

=item C<wait_for_file> - Waits for the file specified by option 'path'

Polling frequency defaults to once every five seconds and is set by the option
C<rate>. If option C<timeout> is set and the elapsed runtime exceeds this,
exit with a non zero return code (fail)

=cut

sub wait_for_file : method {
   my $self = shift;

   throw Unspecified, ['option path'] unless exists $self->options->{path};

   my $path = io $self->options->{path};

   $path = $path->absolute($self->config->vardir) unless $path->is_absolute;

   my $delete_first = $self->next_argv // NUL;

   $path->unlink if $delete_first && $path->exists;

   my $rate    = $self->options->{rate} // 5;
   my $timeout = $self->options->{timeout} // 0;

   while (!$path->exists) {
      throw 'Timedout after [_1] seconds', [$timeout]
         if $timeout and elapsed > $timeout;

      sleep $rate;
   }

   return OK;
}

# Private methods
sub _kill_job {
   my $self    = shift;
   my $pidfile = $self->pidfile;

   return 'File ${pidfile} not found' unless $pidfile->exists;

   my $pid = $pidfile->chomp->getline;

   kill 'TERM', $pid;
   $pidfile->unlink;

   return "Process ${pid} killed";
}

sub _send_event {
   my ($self, $transition, $options) = @_;

   $options //= {};

   my $runid  = $self->runid;
   my $prefix = "SendEvent.${transition}[${runid}]";
   my $job_id = $options->{job_id} // $self->job_id;
   my $rv     = $options->{rv};
   my $event  = {
      job_id     => $job_id,
      pid        => $PID,
      runid      => $runid,
      transition => $transition,
   };

   $event->{rv} = $rv if defined $rv;

   $self->log->debug("${prefix}: " . (defined $rv ? "Rv ${rv}" : "Pid ${PID}"));

   my $encrypted = encrypt $self->token, $self->transcoder->encode($event);
   my $path      = sprintf $self->config->uri_template->{event}, $runid;
   my $template  = $self->protocol . '://%s:' . $self->port . $path;

   for my $server (@{$self->servers}) {
      try {
         my $uri = sprintf $template, $server;
         my $res = $self->post_as_json($uri, { event => $encrypted });

         unless ($res->{success}) {
            my $message = $self->transcoder->decode($res->{content})->{message};

            throw 'Post response - [_1]', [$res->{status} . " ${message}"];
         }

         $self->log->debug("${prefix}: " . $res->{content}->{message});
      }
      catch { $self->log->error("${prefix}: ${_}") };
   }

   return;
}

# TODO: Env vars job_name runid namespace(dev, test, live) pid
sub _run_command {
   my $self    = shift;
   my $pidfile = $self->pidfile;
   my $runid   = $self->runid;
   my $options = { expected_rv => 255 };

   $options->{err} = $self->errfile if $self->errfile;
   $options->{out} = $self->outfile if $self->outfile;

   $self->_set_program_name;

   try {
      local $SIG{TERM} = sub {
         $pidfile->unlink if $pidfile->exists;
         kill 'TERM', 0;
         exit FAILED;
      };

      $self->_send_event('started');

      _chdir($self->directory) if $self->directory;

      my $result = $self->run_cmd($self->command, $options);

      $self->_send_event('finish', { rv => $result->rv });
   }
   catch {
      $self->log->error("RunCommand[${runid}]: ${_}");
      $self->_send_event('terminate');
   };

   $pidfile->unlink if $pidfile->exists;
   return OK;
}

sub _set_program_name {
   my $self   = shift;
   my $config = $self->config;

   return $PROGRAM_NAME = $config->prefix . '-worker - ' . $self->runid;
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

=back

=head1 Diagnostics

None

=head1 Dependencies

You need to install the GNU MP library (C<libgmp3-dev>) which is required by
L<Crypt::SRP> to install this distribution

=over 3

=item L<Authen::HTTP::Signature>

=item L<Class::Usul::Cmd>

=item L<Crypt::SRP>

=item L<Data::Record>

=item L<File::DataClass>

=item L<HTTP::Tiny>

=item L<JSON::MaybeXS>

=item L<Moo>

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
