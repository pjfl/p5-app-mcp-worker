package App::MCP::Worker::Role::UserPassword;

use Class::Usul::Cmd::Constants qw( AS_PASSWORD EXCEPTION_CLASS FALSE NUL TRUE);
use File::DataClass::Types      qw( Path );
use Class::Usul::Cmd::Util      qw( decrypt encrypt load_file dump_file );
use Unexpected::Functions       qw( throw Unspecified );
use Moo::Role;

requires qw( config get_line );

has 'rc_file' =>
   is      => 'lazy',
   isa     => Path,
   coerce  => TRUE,
   default => sub { shift->config->home->catfile('.mcprc.json') };

# Public methods
sub get_user_password {
   my ($self, $user_name) = @_;

   throw Unspecified, ['user name'] unless $user_name;

   my $data     = $self->local_config;
   my $password = $data->{"${user_name}_password"};

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

   my $data = $self->local_config;

   $data->{"${user_name}_password"} = encrypt NUL, $password;

   $self->local_config($data);
   $self->info('Updated user password', { name => 'Worker.set_user_password' });
   return;
}

# Private methods
sub local_config {
   my ($self, $data) = @_;

   my $path = $self->rc_file;

   if ($data) {
      dump_file($path->assert, $data);
      return $data;
   }

   return load_file($path, TRUE) // {} if $path->exists;

   return {};
}

use namespace::autoclean;

1;

__END__

=pod

=encoding utf-8

=head1 Name

App::MCP::Worker::Role::UserPassword - Obtain and store the user passsword

=head1 Synopsis

   use Moo;

   with 'App::MCP::Worker::Role::UserPassword';

=head1 Description

Obtain and store the user passsword

=head1 Configuration and Environment

Defines the following attributes;

=over 3

=item C<rc_file>

=back

=head1 Subroutines/Methods

Defined the following methods;

=over 3

=item C<get_user_password>

=item C<set_user_password>

=back

=head1 Diagnostics

None

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
