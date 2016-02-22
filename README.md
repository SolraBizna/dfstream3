Overview
========

This is a shim that makes Dwarf Fortress act as a TTTP server. It is compatible
with every Linux version of Dwarf Fortress that I've tried it with, all the way
back to when it first started using SDL. It's also compatible with all versions
of DFHack.

This enables many possibilities not supported by ordinary Dwarf Fortress:

- Run DF on your beefy workstation, while *playing* it on your low-powered
laptop.
- Switch from one computer to another without having to restart DF.
- Show your friends around your awesome fortress, or help them learn the game.
- NCIS-style cooperative play; two players, one virtual keyboard and screen!

It is not dependent on any reverse engineered aspect of Dwarf Fortress. It only
requires that the `PRINT_MODE` and font be set correctly. As such, it is
instantly compatible with any new Dwarf Fortress release.

In terms of what it can do, it's similar to the old `dfterm` project. The main
differences are that it requires a TTTP client (rather than any telnet client),
that it does not currently have any form of in-band chat feature, and that it
is currently maintained. On the plus side, TTTP includes a compression scheme
designed to make the bandwidth usage tiny, even compared to telnet. (In fact,
a prototype of this shim was used to test that compression!)

It is **not**, nor will it **ever** be, compatible with graphical tilesets, nor
TTF (fancy) fonts, nor Windows servers! The first two are because of the nature
of the TTTP protocol, the latter is because Windows doesn't have an equivalent
of the `pth` library. (Note that while Windows can't run the *server*, Windows
TTTP *clients* are more than capable of connecting to it.)

Setup
=====

- In Dwarf Fortress's `data/init.txt`...
  - Set `[WINDOWED:YES]`
  - Set `[WINDOWEDX:...]` and `[WINDOWEDY:...]` to the window dimensions you
want
  - Set `[FONT:bitfont.png]`
  - Set `[RESIZABLE:NO]`
  - Set `[PRINT_MODE:2D]`
- Copy `bitfont.png` into Dwarf Fortress's `data/art/` directory

The shim is compatible with fullscreen mode, with the appropriate settings.

Bitfont is designed to be quick for the shim to read in a compatible fashion.
It is extremely non-human readable. Don't accidentally start Dwarf Fortress
with it without this shim. (Unfortunately, this font will also used for map
exports. A decoder for exported maps that have been mangled this way wouldn't
be difficult to write.)

Running
=======

Regardless of whether you're using DFHack or not, you will need to set some
environment variables:

- `DFSTREAM3_MASTER_USERNAME` must be set to the username you wish to use for
the "master" user. You may give it a blank value if you want guests to be
"masters".
- `DFSTREAM3_MASTER_PASSWORD` must be set to the password for the "master"
user. A blank value *is* a valid (though not very secure) password.
- `DFSTREAM3_PORT` may optionally be set to the port to listen on. If it isn't
specified, dfstream will listen on the standard TTTP port (7028).

If you are *not* using DFHack, place `dfstream3.so` into the `LD_PRELOAD`
environment variable and start DF normally, like so:

    DFSTREAM3_MASTER_USERNAME=jdoe DFSTREAM3_MASTER_PASSWORD=bobbleheads LD_PRELOAD=/home/jdoe/dfstream3/dfstream3.so ./df

If you *are* using DFHack, you must instead place `dfstream3.so` into the
`PRELOAD_LIB` environment variable when you start DFHack, like so:

    DFSTREAM3_MASTER_USERNAME=jdoe DFSTREAM3_MASTER_PASSWORD=bobbleheads PRELOAD_LIB=/home/jdoe/dfstream3/dfstream3.so ./dfhack

Now simply connect the TTTP client of your choice and enjoy! I recommend [this
one](https://github.com/SolraBizna/tttpclient/releases/), partly because I
wrote it, and partly because it's the only one I know exists.

Passwords
=========

Putting the password directly in an environment variable is bad. dfstream
supports, instead, placing the SRP verifier into environment variables. This
prevents an attacker with access to your `/proc` from simply getting the
password, but doesn't prevent them from bruteforcing it. Instead of setting
`DFSTREAM3_MASTER_PASSWORD`, you would set `DFSTREAM3_MASTER_SALT` and
`DFSTREAM3_MASTER_VERIFIER` appropriately. An external tool is needed for
manual creation of SRP verifiers as used by TTTP. (As far as I know, one does
not currently exist.)

Of course, if an attacker can read your `/proc`, you might have bigger problems
on your hands...
