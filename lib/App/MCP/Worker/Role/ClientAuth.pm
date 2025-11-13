package App::MCP::Worker::Role::ClientAuth;

use Class::Usul::Cmd::Constants qw( EXCEPTION_CLASS FALSE NUL TRUE );
use HTTP::Request::Common       qw( GET POST );
use Unexpected::Types           qw( Int NonEmptySimpleStr );
use Class::Usul::Cmd::Util      qw( distname );
use Digest                      qw( );
use Digest::MD5                 qw( md5_hex );
use JSON::MaybeXS               qw( );
use MIME::Base64                qw( decode_base64 encode_base64 );
use Ref::Util                   qw( is_hashref );
use Sys::Hostname               qw( hostname );
use Type::Utils                 qw( class_type );
use Unexpected::Functions       qw( throw Unspecified );
use Authen::HTTP::Signature;
use Crypt::SRP;
use HTTP::Tiny;
use Try::Tiny;
use Moo::Role;
use Class::Usul::Cmd::Options;

requires qw( config get_user_password log );

option 'key_id' =>
   is            => 'lazy',
   isa           => NonEmptySimpleStr,
   documentation => 'Name of the private key file. Defaults to app-mcp',
   default       => sub { distname shift->config->appclass },
   format        => 's',
   short         => 'k';

option 'user_name' =>
   is            => 'lazy',
   isa           => NonEmptySimpleStr,
   documentation => 'Name in the user table and .mcprc file',
   default       => sub { shift->config->prefix },
   format        => 's',
   short         => 'u';

# Private attributes
has '_fetch_timeout' => is => 'ro', isa => Int, default => 30;

has '_srp' =>
   is      => 'lazy',
   isa     => class_type('Crypt::SRP'),
   default => sub { Crypt::SRP->new( 'RFC5054-2048bit', 'SHA512' ) },
   reader  => 'srp';

has '_transcoder' =>
   is      => 'lazy',
   isa     => class_type(JSON::MaybeXS::JSON),
   default => sub { JSON::MaybeXS->new( convert_blessed => TRUE )  },
   reader  => 'transcoder';

has '_user_agent'  =>
   is      => 'lazy',
   isa     => class_type('HTTP::Tiny'),
   default => sub { HTTP::Tiny->new( timeout => shift->_fetch_timeout ) },
   reader  => 'user_agent';

# Public methods
sub authenticate_session {
   my ($self, $uri, $opts) = @_;

   $opts //= {};
   throw Unspecified, ['uri'] unless $uri;
   throw Unspecified, ['template'] unless $opts->{template};

   my $username = $opts->{user_name} // $self->user_name;
   my $password = $opts->{password } // $self->get_user_password($username);
   my $raw_key  = ($self->srp->client_compute_A)[0];

   $self->log->debug('Auth pubic key ' . (md5_hex $raw_key));

   my $keys_uri = $uri . sprintf $opts->{template}->{exchange_keys}, $username;
   my $pub_key  = encode_base64 $raw_key;
   my $res      = $self->get_with_sig($keys_uri, { public_key => $pub_key });
   my $token    = $self->_compute_token($username, $password, $res);
   my $auth_uri = $uri . sprintf $opts->{template}->{authenticate}, $username;

   $res = $self->post_as_json($auth_uri, { M1_token => $token });

   throw 'User [_1] authentication failure code [_2]: [_3]',
      [$username, $res->{status}, $res->{reason}] unless $res->{success};

   my $content  = $res->{content};

   throw 'User [_1] M2 token verification failure', [$username]
      unless $self->srp->client_verify_M2(decode_base64 $content->{M2_token});

   $self->log->debug("User ${username} Session-Id " . $content->{id});

   my $shared_secret = encode_base64 $self->srp->get_secret_K;

   return { id => $content->{id}, shared_secret => $shared_secret };
}

sub get_with_sig {
   my ($self, $uri, $content) = @_;

   my $query = NUL;

   # TODO: If $uri was_a URI::http[s] then we can use query_form
   for (keys %{ $content // {} }) {
      $query .= $query ? '&' : '?'; $query .= "${_}=".$content->{ $_ };
   }

   my $req = GET $uri . $query;

   $req->protocol('HTTP/1.1');

   my $key = $self->_read_private_key;
   my $signer = Authen::HTTP::Signature->new(
      headers => ['request-line'], key => $key, key_id => hostname
   );

   return $self->_decoded_response_to_signed_request($signer->sign($req));
}

sub post_as_json {
   my ($self, $uri, $content) = @_;

   my $digest = Digest->new('SHA-512');

   $content = $self->transcoder->encode($content);
   $digest->add($content);

   my $req = POST $uri,
      'Content-SHA512' => $digest->hexdigest,
      'Content-Type'   => 'application/json',
      'Content'        => $content;
   my $key = $self->_read_private_key;
   # TODO: Why doest hmac-sha512 not work?
   my $signer = Authen::HTTP::Signature->new(
      headers => ['Content-SHA512'], key => $key, key_id => hostname
   );

   return $self->_decoded_response_to_signed_request($signer->sign($req));
}

# Private methods
sub _compute_token {
   my ($self, $username, $password, $res) = @_;

   throw 'User [_1] authentication failure code [_2]: [_3]',
      [$username, $res->{status}, $res->{reason}] unless $res->{success};

   my $content = $res->{content};
   my $server_pub_key = decode_base64($content->{public_key});

   $self->log->debug('Auth server pub key ' . (md5_hex $server_pub_key));
   $self->log->debug('Client init ' . (md5_hex $username . $content->{salt}));

   throw 'User [_1] server public key verification failure', [$username]
      unless $self->srp->client_verify_B($server_pub_key);

   $self->srp->client_init($username, $password, $content->{salt});

   my $token = $self->srp->client_compute_M1;

   $self->log->debug('Auth M1 token ' . (md5_hex $token));
   return encode_base64 $token;
}

sub _decoded_response_to_signed_request {
   my ($self, $req) = @_;

   my $options = { content => $req->content, headers => $req->headers };
   my $res     = $self->user_agent->request($req->method, $req->uri, $options);

   return $res unless $res->{success};

   try   { $res->{content} = $self->transcoder->decode($res->{content}) }
   catch { $res->{reason} = "${_}"; $res->{success} = FALSE };

   return $res;
}

my $private_key_cache = {};

sub _read_private_key {
   my $self = shift;
   my $key  = $private_key_cache->{$self->key_id};

   return $key if $key;

   my $ssh_dir  = $self->config->home->catdir('.ssh');
   my $ssh_file = $ssh_dir->catfile($self->key_id . '.priv');

   return $private_key_cache->{$self->key_id} = $ssh_file->all;
}

use namespace::autoclean;

1;

__END__

=pod

=encoding utf-8

=head1 Name

App::MCP::Worker::Role::ClientAuth - One-line description of the modules purpose

=head1 Synopsis

   with 'App::MCP::Worker::Role::ClientAuth';
   # Brief but working code examples

=head1 Description

=head1 Configuration and Environment

Defines the following attributes

=over 3

=item C<key_id>

=item C<user_name>

=back

=head1 Subroutines/Methods

=head2 C<authenticate_session>

=head2 C<get_with_sig>

=head2 C<post_as_json>

=head1 Diagnostics

=head1 Dependencies

=over 3

=item L<Class::Usul::Cmd>

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
