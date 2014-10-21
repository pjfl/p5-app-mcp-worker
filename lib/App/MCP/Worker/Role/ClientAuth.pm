package App::MCP::Worker::Role::ClientAuth;

use feature 'state';
use namespace::autoclean;

use Authen::HTTP::Signature;
use Class::Usul::Constants qw( EXCEPTION_CLASS NUL );
use Class::Usul::Functions qw( base64_decode_ns base64_encode_ns
                               class2appdir is_hashref throw );
use Class::Usul::Types     qw( Object );
use Crypt::SRP;
use Digest                 qw( );
use Digest::MD5            qw( md5_hex );
use HTTP::Request::Common  qw( GET POST );
use JSON::MaybeXS          qw( );
use LWP::UserAgent;
use Sys::Hostname;
use Try::Tiny;
use Unexpected::Functions  qw( Unspecified );
use Moo::Role;

requires qw( config get_user_password log user_name );

# Private attributes
has '_srp'        => is => 'lazy', isa => Object,
   builder        => sub { Crypt::SRP->new( 'RFC5054-2048bit', 'SHA512' ) },
   reader         => 'srp';

has '_transcoder' => is => 'lazy', isa => Object,
   builder        => sub { JSON::MaybeXS->new  }, reader => 'transcoder';

has '_user_agent' => is => 'lazy', isa => Object,
   builder        => sub { LWP::UserAgent->new }, reader => 'user_agent';

# Public methods
sub authenticate_session {
   my ($self, $uri, $opts) = @_;

   $uri or throw Unspecified, args => [ 'uri' ];
   (is_hashref $opts and $opts->{template})
        or throw Unspecified, args => [ 'template' ];

   my $username = $opts->{user_name} // $self->user_name;
   my $password = $opts->{password } // $self->get_user_password( $username );
   my $raw_key  = ($self->srp->client_compute_A)[ 0 ];

   $self->log->debug( 'Auth pubic key '.(md5_hex $raw_key) );
   $uri .= sprintf $opts->{template}, $username;

   my $pub_key  = base64_encode_ns $raw_key;
   my $res      = $self->get_with_sig( $uri, { public_key => $pub_key } );
   my $token    = $self->_compute_token( $username, $password, $res );

   $res = $self->post_as_json( $uri, { M1_token => $token } );

   my $content  = $res->content;

   $res->is_success
      or throw 'User [_1] authentication failure code [_2]: [_3]',
               args => [ $username, $res->code, $content->{message} ];

   $self->srp->client_verify_M2( base64_decode_ns $content->{M2_token} )
      or throw 'User [_1] M2 token verification failure', args => [ $username ];

   $self->log->debug( "User ${username} Session-Id ".$content->{id} );

   my $shared_secret = base64_encode_ns $self->srp->get_secret_K;

   return { id => $content->{id}, shared_secret => $shared_secret };
}

sub get_with_sig {
   my ($self, $uri, $content) = @_; my $query = NUL;

   # TODO: If $uri was_a URI::http[s] then we can use query_form
   for (keys %{ $content || {} }) {
      $query .= $query ? '&' : '?'; $query .= "${_}=".$content->{ $_ };
   }

   my $req    = GET $uri.$query; $req->protocol( 'HTTP/1.1' );
   my $key    = $self->_read_private_key;
   my $signer = Authen::HTTP::Signature->new
      ( headers => [ 'request-line' ], key => $key, key_id => hostname, );

   return $self->_decoded_response_to_signed_request( $signer->sign( $req ) );
}

sub post_as_json {
   my ($self, $uri, $content) = @_; my $digest = Digest->new( 'SHA-512' );

   $content   = $self->transcoder->encode( $content ); $digest->add( $content );

   my $req    = POST $uri, 'Content-SHA512' => $digest->hexdigest,
                           'Content-Type'   => 'application/json',
                           'Content'        => $content;
   my $key    = $self->_read_private_key;
   # TODO: Why doest hmac-sha512 not work?
   my $signer = Authen::HTTP::Signature->new
      ( headers => [ 'Content-SHA512' ], key => $key, key_id => hostname, );

   return $self->_decoded_response_to_signed_request( $signer->sign( $req ) );
}

# Private methods
sub _compute_token {
   my ($self, $username, $password, $res) = @_; my $content = $res->content;

   $res->is_success
      or throw 'User [_1] authentication failure code [_2]: [_3]',
               args => [ $username, $res->code, $content->{message} ];

   my $server_pub_key = base64_decode_ns( $content->{public_key} );

   $self->log->debug( 'Auth server pub key '.(md5_hex $server_pub_key ) );

   $self->srp->client_verify_B( $server_pub_key )
      or throw 'User [_1] server public key verification failure',
               args => [ $username ];

   $self->srp->client_init( $username, $password, $content->{salt} );

   my $token = $self->srp->client_compute_M1;

   $self->log->debug( 'Auth M1 token '.(md5_hex $token) );
   return base64_encode_ns $token;
}

sub _decoded_response_to_signed_request {
   my ($self, $req) = @_; my $res = $self->user_agent->request( $req );

   try   { $res->content( $self->transcoder->decode( $res->content ) ) }
   catch { $res->content( { message => $res->content } ) };

   return $res;
}

sub _read_private_key {
   my ($self, $key_id) = @_; state $cache //= {};

   $key_id //= class2appdir $self->config->appclass;

   my $key     = $cache->{ $key_id }; $key and return $key;
   my $ssh_dir = $self->config->my_home->catdir( '.ssh' );

   return $cache->{ $key_id } = $ssh_dir->catfile( "${key_id}.priv" )->all;
}

# Private functions
sub __get_hashed_pw {
   my $crypted = shift; my @parts = split m{ [\$] }mx, $crypted;

   return substr $parts[ -1 ], 22;
}

1;

__END__

=pod

=encoding utf8

=head1 Name

App::MCP::Worker::Role::ClientAuth - One-line description of the modules purpose

=head1 Synopsis

   with 'App::MCP::Worker::Role::ClientAuth';
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
http://rt.cpan.org/NoAuth/Bugs.html?Dist=App-MCP-Worker.
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
