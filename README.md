# Name

App::MCP::Worker - Remotely executed worker process

# Version

This documents version v0.2.$Rev: 28 $ of [App::MCP::Worker](https://metacpan.org/pod/App%3A%3AMCP%3A%3AWorker)

# Synopsis

    #!/usr/bin/env perl

    use App::MCP::Worker;

    exit App::MCP::Worker->new_with_options()->run;

# Description

Remotely executed worker process

# Configuration and Environment

Defines the following attributes;

- `job`

    Keys and values of a job definition in JSON format. Set from the command line
    with `-j`

- `port`

    Port number for the remote servers. Defaults to **2012**. Set from the command
    line with `-p`

- `protocol`

    Which network protocol to use. Defaults to **http**. Set from the command line
    with `-P`

- `servers`

    List of servers to send response status to. Defaults to **localhost**. Set from
    the command line with `-s`

- `command`

    The command to execute. Coerced from a string. Defaults to **true**

- `directory`

    The directory from which to execute the command

- `job_id`

    The numeric id of the job record

- `runid`

    Unique string for this run of the command

- `token`

    Used to encrypt the command's returned value

# Subroutines/Methods

Defines the following methods;

- `BUILDARGS`
- `BUILD`
- `create_job` - Creates a new job on an MCP job scheduler
- `dispatch`
- `set_client_password` - Stores the clients API password in a local file

# Diagnostics

None

# Dependencies

You need to install the GNU MP library (`libgmp3-dev`) which is required by
[Crypt::SRP](https://metacpan.org/pod/Crypt%3A%3ASRP) to install this distribution

- [Authen::HTTP::Signature](https://metacpan.org/pod/Authen%3A%3AHTTP%3A%3ASignature)
- [Class::Usul::Cmd](https://metacpan.org/pod/Class%3A%3AUsul%3A%3ACmd)
- [Crypt::SRP](https://metacpan.org/pod/Crypt%3A%3ASRP)
- [Data::Record](https://metacpan.org/pod/Data%3A%3ARecord)
- [File::DataClass](https://metacpan.org/pod/File%3A%3ADataClass)
- [HTTP::Tiny](https://metacpan.org/pod/HTTP%3A%3ATiny)
- [JSON::MaybeXS](https://metacpan.org/pod/JSON%3A%3AMaybeXS)
- [Moo](https://metacpan.org/pod/Moo)
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
