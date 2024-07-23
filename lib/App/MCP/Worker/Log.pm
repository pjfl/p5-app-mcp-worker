package App::MCP::Worker::Log;

use Class::Usul::Cmd::Constants qw( DOT FALSE NUL TRUE USERNAME );
use Class::Usul::Cmd::Types     qw( Bool ConfigProvider );
use Class::Usul::Cmd::Util      qw( now_dt trim );
use HTML::StateTable::Util      qw( escape_formula );
use Ref::Util                   qw( is_arrayref is_coderef );
use Type::Utils                 qw( class_type );
use Text::CSV_XS;
use Moo;

has 'config' => is => 'ro', isa => ConfigProvider, required => TRUE;

has '_csv' =>
   is      => 'ro',
   isa     => class_type('Text::CSV_XS'),
   default => sub {
      return Text::CSV_XS->new({ always_quote => TRUE, binary => TRUE });
   };

has '_debug' =>
   is       => 'lazy',
   isa      => Bool,
   init_arg => 'debug',
   default  => sub {
      my $self  = shift;
      my $debug = $self->config->appclass->env_var('debug');

      return defined $debug ? !!$debug : FALSE;
   };

around 'BUILDARGS' => sub {
   my ($orig, $self, @args) = @_;

   my $attr = $orig->($self, @args);

   if (my $builder = delete $attr->{builder}) {
      $attr->{config} //= $builder->config;
      $attr->{debug} //= $builder->debug;
   }

   return $attr;
};

sub alert {
   return shift->_log('ALERT', NUL, @_);
}

sub debug {
   my $self = shift;

   return unless $self->_debug;

   return $self->_log('DEBUG', NUL, @_);
}

sub error {
   return shift->_log('ERROR', NUL, @_);
}

sub fatal {
   return shift->_log('FATAL', NUL, @_);
}

sub info {
   return shift->_log('INFO', NUL, @_);
}

sub log { # For benefit of P::M::LogDispatch
   my ($self, %args) = @_;

   my $level   = uc $args{level};
   my $message = $args{message};
   my $leader  = $args{name} || (split m{ :: }mx, caller)[-1];

   return if $level =~ m{ debug }imx && !$self->_debug;

   $message = $message->() if is_coderef $message;
   $message = is_arrayref $message ? $message->[0] : $message;

   return $self->_log($level, $leader, $message);
}

sub warn {
   return shift->_log('WARNING', NUL, @_);
}

# Private methods
sub _get_leader {
   my ($self, $message, $context) = @_;

   my $leader;

   if ($context) {
      if ($context->can('leader')) { $leader = $context->leader }
      elsif ($context->can('action') && $context->has_action) {
         my @parts = split m{ / }mx, ucfirst $context->action;

         $leader = $parts[0] . DOT . $parts[-1];
      }
      elsif ($context->can('name')) { $leader = ucfirst $context->name }
   }

   unless ($leader) {
      if ($message =~ m{ \A \S+ : }mx) {
         ($leader, $message) = split m{ : }mx, $message, 2;
      }
      else { $leader = 'Worker' }
   }

   return ($leader, trim $message);
}

sub _log {
   my ($self, $level, $leader, $message, $context) = @_;

   $level   ||= 'ERROR';
   $message ||= 'Unknown';
   $message = "${message}";
   chomp $message;
   $message =~ s{ \n }{. }gmx;

   ($leader, $message) = $self->_get_leader($message, $context) unless $leader;

   my $now      = now_dt->strftime('%Y/%m/%d %T');
   my $username = $context && $context->can('session')
      ? $context->session->username : USERNAME;

   $self->_csv->combine(
      escape_formula $now, $level, $username, $leader, $message
   );

   my $config = $self->config;

   if ($config->can('logfile') && $config->logfile) {
      $config->logfile->appendln($self->_csv->string)->flush;
   }
   else { CORE::warn "${leader}: ${message}\n" }

   return TRUE;
}

use namespace::autoclean;

1;
