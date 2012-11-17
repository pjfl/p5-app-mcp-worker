# @(#)$Id$

package App::MCP::Worker;

use strict;
use version; our $VERSION = qv( sprintf '0.1.%d', q$Rev$ =~ /\d+/gmx );

use Class::Usul::Moose;
use Class::Usul::Constants;
use Class::Usul::Crypt     qw(encrypt);
use Class::Usul::Functions qw(app_prefix pad throw);
use English                qw(-no_match_vars);
use File::HomeDir;
use File::DataClass::IO;
use HTTP::Request::Common  qw(POST);
use LWP::UserAgent;
use MooseX::Types          -declare => [ qw(ServerList) ];
use Storable               qw(nfreeze);
use TryCatch;

extends q(Class::Usul::Programs);

subtype ServerList, as ArrayRef;
coerce  ServerList, from Str, via { [ split SPC, $_ ] };

has 'command'    => is => 'ro', isa => NonEmptySimpleStr, required => TRUE;

has 'port'       => is => 'ro', isa => PositiveInt,       default  => 2012;

has 'protocol'   => is => 'ro', isa => NonEmptySimpleStr, default  => 'http';

has 'job_id'     => is => 'ro', isa => PositiveInt,       required => TRUE;

has 'runid'      => is => 'ro', isa => NonEmptySimpleStr, required => TRUE;

has 'servers'    => is => 'ro', isa => ServerList,        coerce   => TRUE,
   required      => TRUE;

has 'token'      => is => 'ro', isa => NonEmptySimpleStr;

has 'uri_format' => is => 'ro', isa => NonEmptySimpleStr,
   default       => 'api/event?runid=%s';

sub dispatch {
   my $self = shift;

   my $r = $self->run_cmd( [ sub { $self->_run_command } ], { async => TRUE } );

   return $r->out;
}

sub provision {
   my $appclass = shift; $appclass or throw 'No appclass';
   my $prefix   = app_prefix $appclass;
   my $home     = File::HomeDir->my_home;
   my $appldir  = io( [ $home, ".${prefix}" ] );
      $appldir->exists or $appldir->mkpath( 0750 );
   my $logsdir  = $appldir->catdir( 'logs' );
      $logsdir->exists or $logsdir->mkpath( 0750 );
   my $tempdir  = $appldir->catdir( 'tmp' );
      $tempdir->exists or $tempdir->mkpath( 0750 );
   my $cfgfile  = $appldir->catfile( "${prefix}.json" );
      $cfgfile->exists or $cfgfile->print( __config_file_content() );

   return "Provisioned ${appldir}";
}

# Private methods

sub _run_command {
   my $self = shift; my $r;

   $self->_send_event( 'running' );

   try        { $r = $self->run_cmd( [ split SPC, $self->command ] ) }
   catch ($e) { $self->_send_event( 'terminated' ); return }

   $self->_send_event( 'finished', $r );
   return;
};

sub _send_event {
   my ($self, $state, $r) = @_;

   my $runid  = $self->runid;
   my $ua     = LWP::UserAgent->new;
   my $evt    = { job_id => $self->job_id, pid  => $PID, runid => $runid,
                  state  => $state,        type => 'state_update', };
   my $tag    = pad uc $state, 10, SPC, 'left';
   my $prefix = "${tag}[${runid}]: ";

   $self->log->debug( $prefix.($r ? 'Rv '.$r->rv : "Pid ${PID}") );
   $r and $evt->{rv} = $r->rv; $evt = nfreeze $evt;
   $self->token and $evt = encrypt $self->token, $evt;

   for my $server (@{ $self->servers }) {
      my $uri  = $self->protocol."://${server}:".$self->port.'/';
         $uri .= sprintf $self->uri_format, $self->runid;
      my $req  = POST $uri, [ event => $evt ];
      my $res  = $ua->request( $req );

      if ($res->is_success) { $self->log->debug( "${prefix}Code ".$res->code ) }
      else { $self->log->error( $prefix.$res->message ) }
   }

   return;
}

sub __config_file_content {
   return "{\n   \"name\" : \"worker\"\n}\n";
}

__PACKAGE__->meta->make_immutable;

1;

__END__

=pod

=head1 Name

App::MCP::Worker - <One-line description of module's purpose>

=head1 Version

0.1.$Revision$

=head1 Synopsis

   use App::MCP::Worker;
   # Brief but working code examples

=head1 Description

=head1 Configuration and Environment

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
