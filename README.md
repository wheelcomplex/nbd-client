## Synopsis

The Network Block Device is a Linux-originated lightweight block access
protocol that allows one to export a block device to a client.  This client
is designed to run on top of FreeBSD's GEOM gate device driver.

## Caveats

* Only the fixed newstyle NBD handshake is supported.
* TLS and other extensions are not currently supported.
* Only the default (unnamed) export on the default port (10809) is used.

These limitations will likely be fixed in future revisions.

## Usage Example

`nbd-client 192.168.1.101`

This connects to an NBD server and will print the name of the device
created on stdout.  You can then use this device as a regular disk device,
for example:

`zpool create foo ggate0`

## Motivation

Scaleway offers high-density dedicated servers using NBD to attach storage
to each machine.  FreeBSD lacks an NBD client, so Scaleway does not support
FreeBSD.  This project aims to implement an NBD client so that Scaleway can
offer FreeBSD on their servers.

## Compiling

`make`

Note: This project expects to be compiled with BSD make, not GNU make.

## License

BSD 2-Clause License

Copyright (c) 2016, Ryan Moeller
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
