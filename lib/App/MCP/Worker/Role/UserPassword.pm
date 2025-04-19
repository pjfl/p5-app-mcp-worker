package App::MCP::Worker::Role::UserPassword;

use Class::Usul::Cmd::Constants qw( AS_PASSWORD EXCEPTION_CLASS FALSE NUL TRUE);
use File::DataClass::Types      qw( Path );
use Class::Usul::Cmd::Util      qw( decrypt encrypt );
use Unexpected::Functions       qw( throw Unspecified );
use File::DataClass::Schema;
use Moo::Role;

requires qw( config get_line );

has 'rc_file' =>
   is      => 'lazy',
   isa     => Path,
   coerce  => TRUE,
   default => sub { shift->config->home->catfile('.mcprc.json') };

has '_file_schema' =>
   is      => 'lazy',
   default => sub { File::DataClass::Schema->new(storage_class => 'Any') };

# Public methods
sub get_user_password {
   my ($self, $user_name) = @_;

   throw Unspecified, ['user name'] unless $user_name;

   my $data     = $self->_local_config;
   my $password = $data->{users}->{$user_name};

   if ($password) { $password = decrypt NUL, $password }
   else { $password = $self->get_line('+Enter password', AS_PASSWORD) };

   return $password;
}

sub set_user_password {
   my ($self, $user_name, $password) = @_;

   throw Unspecified, ['user name'] unless $user_name;

   unless ($password) {
      $password = $self->get_line('+Enter password', AS_PASSWORD);

      my $again = $self->get_line('+Again', AS_PASSWORD);

      throw 'Passwords do not match' unless $password eq $again;
   }

   throw Unspecified, ['password'] unless $password;

   my $data = $self->_local_config;

   $data->{users}->{$user_name} = encrypt NUL, $password;

   $self->_local_config($data);
   $self->info('Updated user password', { name => 'Worker.set_user_password' });
   return;
}

# Private methods
sub _local_config {
   my ($self, $data) = @_;

   my $path = $self->rc_file;
   my $default = { users => {} };

   if ($data) {
      $self->_file_schema->dump({ path => $path->assert, data => $data });
      return $data;
   }

   return $self->_file_schema->load($path) // $default if $path->exists;

   return $default;
}

use namespace::autoclean;

1;

__END__

=pod

=encoding utf-8

=head1 Name

App::MCP::Worker::Role::UserPassword - One-line description of the modules purpose

=head1 Synopsis

   with 'App::MCP::Worker::Role::UserPassword';
   # Brief but working code examples

=head1 Description

=head1 Configuration and Environment

Defines the following attributes;

=over 3

=back

=head1 Subroutines/Methods

=head2 get_user_password

=head2 set_user_password

=head1 Diagnostics

=head1 Dependencies

=over 3

=item L<Class::Usul::Cmd>

=back

=head1 Incompatibilities

There are no known incompatibilities in this module

=head1 Bugs and Limitations

There are no known bugs in this module. Please report problems to
http://rt.cpan.org/NoAuth/Bugs.html?Dist=App-MCP.
Patches are welcome

=head1 Acknowledgements

Larry Wall - For the Perl programming language

=head1 Author

Peter Flanigan, C<< <pjfl@cpan.org> >>

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
