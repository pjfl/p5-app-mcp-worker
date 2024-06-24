package App::MCP::Worker::Role::UserPassword;

use Class::Usul::Constants   qw( AS_PASSWORD EXCEPTION_CLASS FALSE NUL TRUE );
use Class::Usul::Crypt::Util qw( decrypt_from_config encrypt_for_config
                                 is_encrypted );
use Class::Usul::Functions   qw( throw );
use File::DataClass::Types   qw( Path );
use Unexpected::Functions    qw( Unspecified );
use Moo::Role;

requires qw( config file get_line );

has 'rc_file' =>
   is      => 'lazy',
   isa     => Path,
   coerce  => TRUE,
   default => sub { shift->config->my_home->catfile('.mcprc.json') };

# Public methods
sub get_user_password {
   my ($self, $user_name) = @_;

   my $password = $self->_read_rc_file->{users}->{$user_name}
               // $self->get_line('+Enter password', AS_PASSWORD);

   $password = decrypt_from_config $self->config, $password
      if $password and is_encrypted($password);

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

   my $data = $self->_read_rc_file;

   $data->{users}->{$user_name} = is_encrypted($password)
      ? $password : encrypt_for_config $self->config, $password;

   $self->_write_rc_file($data);
   return;
}

# Private methods
sub _read_rc_file {
   my $self = shift;

   return { users => {} } unless $self->rc_file->exists;

   return $self->file->data_load(paths => [$self->rc_file]);
}

sub _write_rc_file {
   my ($self, $data) = @_;

   return $self->file->data_dump(data => $data, path => $self->rc_file);
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

=item L<Class::Usul>

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
