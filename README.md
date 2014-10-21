# Name

App::MCP::Worker - Remotely executed worker process

# Version

This documents version v0.2.$Rev: 15 $ of [App::MCP::Worker](https://metacpan.org/pod/App::MCP::Worker)

# Synopsis

    use App::MCP::Worker;
    # Brief but working code examples

# Description

# Configuration and Environment

Defines the following attributes;

- `command`
- `directory`
- `job_id`
- `port`
- `protocol`
- `runid`
- `servers`
- `token`
- `uri_template`

# Subroutines/Methods

## create\_job - Creates a new job on an MCP job scheduler

## set\_client\_password - Stores the clients API password in a local file

# Diagnostics

# Dependencies

You need to install the GNU MP library (`libgmp3-dev`) which is required by
[Crypt::SRP](https://metacpan.org/pod/Crypt::SRP) to install this distribution

- [namespace::autoclean](https://metacpan.org/pod/namespace::autoclean)
- [Authen::HTTP::Signature](https://metacpan.org/pod/Authen::HTTP::Signature)
- [Class::Usul](https://metacpan.org/pod/Class::Usul)
- [Crypt::SRP](https://metacpan.org/pod/Crypt::SRP)
- [Data::Record](https://metacpan.org/pod/Data::Record)
- [File::DataClass](https://metacpan.org/pod/File::DataClass)
- [JSON::MaybeXS](https://metacpan.org/pod/JSON::MaybeXS)
- [LWP::UserAgent](https://metacpan.org/pod/LWP::UserAgent)
- [Moo](https://metacpan.org/pod/Moo)
- [Regexp::Common](https://metacpan.org/pod/Regexp::Common)
- [Try::Tiny](https://metacpan.org/pod/Try::Tiny)
- [Type::Tiny](https://metacpan.org/pod/Type::Tiny)
- [Unexpected](https://metacpan.org/pod/Unexpected)

# Incompatibilities

There are no known incompatibilities in this module

# Bugs and Limitations

There are no known bugs in this module.
Please report problems to the address below.
Patches are welcome

# Acknowledgements

Larry Wall - For the Perl programming language

# Author

Peter Flanigan, `<pjfl@cpan.org>`

# License and Copyright

Copyright (c) 2014 Peter Flanigan. All rights reserved

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. See [perlartistic](https://metacpan.org/pod/perlartistic)

This program is distributed in the hope that it will be useful,
but WITHOUT WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE
