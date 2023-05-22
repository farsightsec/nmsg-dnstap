# NMSG Dnstap Tool

`nmsg-dnstap` takes Frame Streams data as input and sends it in nmsg format to ZeroMQ endpoints. The data is not filtered.

## Building

	sh autogen.sh
	./configure
	make

## Usage

	nmsg-dnstap [ -w zep ... ] [ -s so ... ]
		[ -u socket-path ] [ -a IP -p port ]
		[ -t content-type ] [ -b buffer-size ]
		[ -d [-d ...] ]

The `-w` argument specifies a ZeroMQ endpoint for sending the nmsg data.

The `-s` argument specifies a socket endpoint (addr/port) for sending the nmsg data. There must be at least one '-w' or '-s' endpoint specified.

The `-u` argument gives a path for a UNIX domain socket to receive the Frame Streams data. Either this, or the `-a`/`-p` options must be used.

The `-a` argument specifies an IP-address to listen on to receive Frame Streams data. The `-p` option must be specified as well. Use either `-a`/`-p` or `-u`.

The `-p` argument specifies the TCP port to listen on to receive Frame Streams data. This is used in conjunction with the `-a` argument.

The `-b' argument specifies the maximum frame size which will be accepted. Anything larger than this will be discarded. The default is 262144 (256KiB).

The `-t` argument sets the content-type to receive from the Frame Streams connection.

## Why?

DNS Servers send dnstap data in Frame Streams format; this utility makes the dnstap data available to nmsgtool for further processing.

