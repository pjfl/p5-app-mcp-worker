# @(#)$Ident: Worker.pm 2013-08-07 00:42 pjf ;

package App::MCP::Worker;

use 5.010001;
use namespace::sweep;
use version; our $VERSION = qv( sprintf '0.1.%d', q$Rev: 5 $ =~ /\d+/gmx );

use Class::Usul::Constants;
use Class::Usul::Crypt      qw( encrypt );
use Class::Usul::Functions  qw( pad throw );
use Cwd                     qw( getcwd );
use English                 qw( -no_match_vars );
use File::DataClass::Types  qw( ArrayRef Directory NonEmptySimpleStr
                                NonZeroPositiveInt SimpleStr Str );
use HTTP::Request::Common   qw( POST );
use LWP::UserAgent;
use Moo;
use MooX::Options;
use Storable                qw( nfreeze );
use TryCatch;
use Type::Utils             qw( as coerce from subtype via );

extends q(Class::Usul::Programs);
with    q(Class::Usul::TraitFor::UntaintedGetopts);

my $ServerList = subtype as ArrayRef;

coerce $ServerList, from Str, via { [ split SPC, $_ ] };

option 'command'    => is => 'ro', isa => NonEmptySimpleStr,  required => TRUE;

option 'directory'  => is => 'ro', isa => Directory | SimpleStr;

option 'port'       => is => 'ro', isa => NonZeroPositiveInt, default => 2012;

option 'protocol'   => is => 'ro', isa => NonEmptySimpleStr,  default => 'http';

option 'job_id'     => is => 'ro', isa => NonZeroPositiveInt, required => TRUE;

option 'runid'      => is => 'ro', isa => NonEmptySimpleStr,  required => TRUE;

option 'servers'    => is => 'ro', isa => $ServerList,        required => TRUE,
   coerce           => $ServerList->coercion;

option 'token'      => is => 'ro', isa => SimpleStr;

option 'uri_format' => is => 'ro', isa => NonEmptySimpleStr,
   default          => 'api/event?runid=%s';

# Public methods
sub dispatch {
   my $self = shift;

   my $r = $self->run_cmd( [ sub { $self->_run_command } ], { async => TRUE } );

   return $r->out;
}

# Private methods
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

   my $runid  = $self->runid;
   my $ua     = LWP::UserAgent->new;
   my $event  = { job_id => $self->job_id, pid        => $PID,
                  runid  => $runid,        transition => $transition, };
   my $prefix = (pad uc $transition, 9, SPC, 'left')."[${runid}]: ";

   $self->log->debug( $prefix.($r ? 'Rv '.$r->rv : "Pid ${PID}") );
   $r and $event->{rv} = $r->rv; $event = nfreeze $event;
   $self->token and $event = encrypt $self->token, $event;

   for my $server (@{ $self->servers }) {
      my $uri  = $self->protocol."://${server}:".$self->port.'/';
         $uri .= sprintf $self->uri_format, $self->runid;
      my $res  = $ua->request( POST $uri, [ event => $event ] );

      if ($res->is_success) { $self->log->debug( "${prefix}Code ".$res->code ) }
      else { $self->log->error( $prefix.$res->message ) }
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

App::MCP::Worker - <One-line description of module's purpose>

=head1 Version

This documents version v0.1.$Rev: 5 $

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

Copyright (c) 2012 Peter Flanigan. All rights reserved

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
