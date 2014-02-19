package App::MCP::Worker::Crypt::SRP::Blowfish;

use strict;
use warnings;
use parent 'Crypt::SRP';

use Crypt::Eksblowfish::Bcrypt qw( bcrypt );

sub new {
   my ($class, $group, $hash, $format, @args) = @_;

   $group ||= 'RFC5054-2048bit'; $hash ||= 'SHA512'; $format ||= 'base64url';

   return $class->next::method( $group, $hash, $format, @args );
}

sub client_init {
  my ($self, $Bytes_I, $Bytes_P, $Bytes_s, $Bytes_B, $Bytes_A, $Bytes_a) = @_;

  $self->{Bytes_I} = $Bytes_I;
  $self->{Bytes_P} = $Bytes_P;
  $self->{Bytes_s} = $Bytes_s;
  $self->{Num_x  } = $self->_calc_x();

  defined $Bytes_B
     and $self->{Num_B} = __bytes2bignum( $self->_unformat( $Bytes_B ) );
  defined $Bytes_A
     and $self->{Num_A} = __bytes2bignum( $self->_unformat( $Bytes_A ) );
  defined $Bytes_a
     and $self->{Num_a} = __bytes2bignum( $self->_unformat( $Bytes_a ) );
  return $self;
}

sub server_init {
   my ($self, $Bytes_I, $salted_hashed_pw, $Bytes_A, $Bytes_B, $Bytes_b) = @_;

   my $Bytes_x = $self->_unformat( __get_hashed_pw( $salted_hashed_pw ) );

   $self->{Bytes_I} = $Bytes_I;
   $self->{Num_x  } = __bytes2bignum( $Bytes_x );
   $self->{Bytes_s} = __get_salt( $salted_hashed_pw );
   $self->{Num_v  } = __bytes2bignum( $self->_calc_v );

   defined $Bytes_A
      and $self->{Num_A} = __bytes2bignum( $self->_unformat( $Bytes_A ) );
   defined $Bytes_B
      and $self->{Num_B} = __bytes2bignum( $self->_unformat( $Bytes_B ) );
   defined $Bytes_b
      and $self->{Num_b} = __bytes2bignum( $self->_unformat( $Bytes_b ) );
   return $self;
}

sub _calc_x {
  my $self = shift;

  (defined $self->{Bytes_s} and defined $self->{Bytes_P}) or return;

  my $salted_hashed_pw = bcrypt( $self->{Bytes_P}, $self->{Bytes_s} );
  my $Bytes_x = $self->_unformat( __get_hashed_pw( $salted_hashed_pw ) );
  my $Num_x   = __bytes2bignum( $Bytes_x );

  return $Num_x;
}

sub __bytes2bignum {
   return Crypt::SRP::_bytes2bignum( @_ );
}

sub __get_hashed_pw {
   my $password = shift; my @parts = split m{ [\$] }mx, $password;

   return substr $parts[ -1 ], 22;
}

sub __get_salt {
   my $password = shift; my @parts = split m{ [\$] }mx, $password;

   $parts[ -1 ] = substr $parts[ -1 ], 0, 22;

   return join '$', @parts;
}

1;

__END__

=pod

=encoding utf8

=head1 Name

App::MCP::Worker::Crypt::SRP::Blowfish - One-line description of the modules purpose

=head1 Synopsis

   use App::MCP::Crypt::SRP::Blowfish;
   # Brief but working code examples

=head1 Description

=head1 Configuration and Environment

Defines the following attributes;

=over 3

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

There are no known bugs in this module. Please report problems to
http://rt.cpan.org/NoAuth/Bugs.html?Dist=App-MCP.
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
# vim: expandtab shiftwidth=3:
