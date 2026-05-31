package App::MCP::Worker::Role::ClientAuth;

use Class::Usul::Cmd::Constants qw( EXCEPTION_CLASS FALSE NUL SPC TRUE );
use HTTP::Request::Common       qw( GET POST );
use Unexpected::Types           qw( Int NonEmptySimpleStr );
use Class::Usul::Cmd::Util      qw( distname );
use Digest::MD5                 qw( md5_hex );
use MIME::Base64                qw( decode_base64url encode_base64url );
use Ref::Util                   qw( is_hashref );
use Sys::Hostname               qw( hostname );
use Type::Utils                 qw( class_type );
use Unexpected::Functions       qw( throw Unspecified );
use Digest                      qw( );
use JSON::MaybeXS               qw( );
use Authen::HTTP::Signature;
use Crypt::SRP;
use HTTP::Tiny;
use Try::Tiny;
use Moo::Role;
use Class::Usul::Cmd::Options;

requires qw( config get_user_password log );

=pod

=encoding utf-8

=head1 Name

App::MCP::Worker::Role::ClientAuth - Client Authentication

=head1 Synopsis

   use Moo;

   with 'App::MCP::Worker::Role::ClientAuth';

=head1 Description

Client Authentication

=head1 Configuration and Environment

Defines the following attributes;

=over 3

=item C<json_parser>

An instance of the JSON encoder/decoder

=cut

has 'json_parser' =>
   is      => 'lazy',
   isa     => class_type(JSON::MaybeXS::JSON),
   default => sub { JSON::MaybeXS->new( convert_blessed => TRUE )  };

=item C<key_id>

Name of the private key file. Defaults to B<app-mcp-worker>. Set from the
command line with C<-k>

=cut

option 'key_id' =>
   is            => 'lazy',
   isa           => NonEmptySimpleStr,
   documentation => 'Name of the private key file. Defaults to app-mcp-worker',
   default       => sub { lc distname shift->config->appclass },
   format        => 's',
   short         => 'k';

=item C<user_name>

Name in the users table on the server and .mcprc file. Defaults to
B<mcpapi>. Set from the command line with C<-u>

=cut

option 'user_name' =>
   is            => 'lazy',
   isa           => NonEmptySimpleStr,
   documentation => 'Name in the users table on the server and .mcprc file',
   default       => sub { shift->config->prefix . 'api' },
   format        => 's',
   short         => 'u';

# Private attributes
has '_fetch_timeout' => is => 'ro', isa => Int, default => 30;

has '_srp' =>
   is      => 'lazy',
   isa     => class_type('Crypt::SRP'),
   default => sub { Crypt::SRP->new('RFC5054-2048bit', 'SHA512') },
   reader  => 'srp';

has '_user_agent'  =>
   is      => 'lazy',
   isa     => class_type('HTTP::Tiny'),
   default => sub { HTTP::Tiny->new( timeout => shift->_fetch_timeout ) };

=back

=cut

sub _fp ($) { # Fingerprint the supplied value. Used for debugging raw keys
   my $v = shift;

   return length($v) . '.' . substr(md5_hex($v), 0, 4);
}

=head1 Subroutines/Methods

Defines the following methods;

=over 3

=item C<authenticate_session>

   $hash_ref = $self->authenticate_session($uri, \%options?);

=cut

sub authenticate_session {
   my ($self, $uri, $opts) = @_;

   $opts //= {};
   throw Unspecified, ['uri'] unless $uri;
   throw Unspecified, ['template'] unless $opts->{template};

   my $username = $opts->{user_name} // $self->user_name;
   my $password = $opts->{password } // $self->get_user_password($username);
   my $raw_key  = ($self->srp->client_compute_A)[0];

   $self->log->debug('Authenticate_session: Client pubkey ' . _fp $raw_key);

   my $pubkey   = encode_base64url $raw_key;
   my $keys_uri = $uri . sprintf $opts->{template}->{exchange_keys}, $username;
   my $res      = $self->signed_get($keys_uri, { public_key => $pubkey });
   my $m1_token = $self->_compute_token($username, $password, $res);
   my $auth_uri = $uri . sprintf $opts->{template}->{authenticate}, $username;

   $res = $self->signed_post($auth_uri, { M1_token => $m1_token });

   throw $res->{status} . SPC . $res->{message} unless $res->{success};

   my $content  = $res->{content};
   my $m2_token = decode_base64url $content->{M2_token};

   throw "User ${username} M2 token verification failed"
      unless $self->srp->client_verify_M2($m2_token);

   my $id = $content->{id};

   $self->log->debug("Authenticate_session: User ${username} session id ${id}");

   my $shared_secret = encode_base64url $self->srp->get_secret_K;

   return { id => $id, shared_secret => $shared_secret };
}

=item C<signed_get>

   $hash_ref = $self->signed_get($uri, \%query_parameters?);

=cut

sub signed_get {
   my ($self, $uri, $content) = @_;

   my $query = NUL;

   # TODO: If $uri was_a URI::http[s] then we can use query_form
   for (keys %{ $content // {} }) {
      $query .= $query ? '&' : '?'; $query .= "${_}=" . $content->{ $_ };
   }

   my $req = GET "${uri}${query}";

   $req->protocol('HTTP/1.1');

   my $key    = $self->_read_private_key;
   my @args   = (headers => ['request-line'], key => $key, key_id => hostname);
   my $signer = Authen::HTTP::Signature->new(@args);

   return $self->_decoded_response_to_signed_request($signer->sign($req));
}

=item C<signed_post>

   $hash_ref = $self->signed_post($uri, $content);

=cut

sub signed_post {
   my ($self, $uri, $content) = @_;

   my $digest = Digest->new('SHA-512');

   $content = $self->json_parser->encode($content);
   $digest->add($content);

   my $req = POST $uri,
      'Content-SHA512' => $digest->hexdigest,
      'Content-Type'   => 'application/json',
      'Content'        => $content;
   my $key  = $self->_read_private_key;
   my @args = (headers => ['Content-SHA512'], key => $key, key_id => hostname);

   # TODO: Why doest hmac-sha512 not work?
   my $signer = Authen::HTTP::Signature->new(@args);

   return $self->_decoded_response_to_signed_request($signer->sign($req));
}

# Private methods
sub _compute_token {
   my ($self, $username, $password, $res) = @_;

   throw 'User [_1] authentication failure: [_2] [_3]',
      [$username, $res->{status}, $res->{message}] unless $res->{success};

   my $content = $res->{content};
   my $server_pubkey = decode_base64url $content->{public_key};

   $self->log->debug('Compute_token: Server pubkey ' . _fp $server_pubkey);
   $self->log->debug("Compute_token: ${username} " . $content->{salt});

   throw 'User [_1] server public key verification failed', [$username]
      unless $self->srp->client_verify_B($server_pubkey);

   $self->srp->client_init($username, $password, $content->{salt});

   my $m1_token = $self->srp->client_compute_M1;

   $self->log->debug('Compute_token: M1 token ' . _fp $m1_token);

   return encode_base64url $m1_token;
}

sub _decoded_response_to_signed_request {
   my ($self, $req) = @_;

   $req->remove_header('::std_case'); # Strange artifact

   my $options = { content => $req->content, headers => $req->headers };
   my $res     = $self->_user_agent->request($req->method, $req->uri, $options);

   try   {
      $res->{content} = $self->json_parser->decode($res->{content});
      $res->{message} = $res->{content}->{message};
   }
   catch { $res->{message} = $res->{content}; $res->{success} = FALSE };

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
