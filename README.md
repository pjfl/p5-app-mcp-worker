# Name

App::MCP::Worker - Remotely executed worker process

# Version

This documents version v0.2.$Rev: 25 $ of [App::MCP::Worker](https://metacpan.org/pod/App%3A%3AMCP%3A%3AWorker)

# Synopsis

    use App::MCP::Worker;

# Description

Remotely executed worker process

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

## `create_job` - Creates a new job on an MCP job scheduler

## `dispatch`

## `set_client_password` - Stores the clients API password in a local file

# Diagnostics

None

# Dependencies

You need to install the GNU MP library (`libgmp3-dev`) which is required by
[Crypt::SRP](https://metacpan.org/pod/Crypt%3A%3ASRP) to install this distribution

- [namespace::autoclean](https://metacpan.org/pod/namespace%3A%3Aautoclean)
- [Authen::HTTP::Signature](https://metacpan.org/pod/Authen%3A%3AHTTP%3A%3ASignature)
- [Class::Usul::Cmd](https://metacpan.org/pod/Class%3A%3AUsul%3A%3ACmd)
- [Crypt::SRP](https://metacpan.org/pod/Crypt%3A%3ASRP)
- [Data::Record](https://metacpan.org/pod/Data%3A%3ARecord)
- [File::DataClass](https://metacpan.org/pod/File%3A%3ADataClass)
- [JSON::MaybeXS](https://metacpan.org/pod/JSON%3A%3AMaybeXS)
- [LWP::UserAgent](https://metacpan.org/pod/LWP%3A%3AUserAgent)
- [Moo](https://metacpan.org/pod/Moo)
- [Regexp::Common](https://metacpan.org/pod/Regexp%3A%3ACommon)
- [Try::Tiny](https://metacpan.org/pod/Try%3A%3ATiny)
- [Type::Tiny](https://metacpan.org/pod/Type%3A%3ATiny)
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
