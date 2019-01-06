# Unicornator

A tool to check source code for cryptographic pitfalls.

**warning: the code is ugly, but it works**

## Install

You can either get & build the tool yourself:

```
$ git clone git@gitlab.na.nccgroup.com:mimoo/unicornator.git
$ go build
```

or download the relevant binary [here](https://github.com/mimoo/unicornator/releases/tag/0.1.0) which are moderately up to date (but feel free to ask me if you need an up to date binary!).

After that just run it:

```sh
$ ./unicornator
Usage: ./unicornator (-level 1|2|3) (-no_ignored) [folder or file]
The default level is 2 (warnings), which will not display severity 1 findings (informationals)
Optional arguments:
-level int
display level of severity: 1 for informationals, 2 for warnings (default), 3 for important (default 2)
-no_ignored
        remove the list of ignored files at the end of the output
```

if `$GOPATH/bin` is in your `PATH` then you should be able to call `unicornator` directly. If it doesn't work you might need to run `go install gitlab.na.nccgroup.com/mimoo/unicornator`

## Usage

To analyze a directory:

```sh
./unicornator -no_ignored /somedirectory
```

To see what files are crypto-y:

```sh
./unicornator -no_ignored -ranking /somedirectory
```

## Features

Non-exhaustive list of things it does:

* It will detect cryptographic files (.pem, .der, .asc, ...)
* It will test cryptographic keys when found
* It will detect weak patterns in know libraries (OpenSSL, BouncyCastle, ...)
* It will detect random crypto nonsense :)

This is a work in progress, so at the moment it's returning a lot of false positives. Help it get better results by sending me its outputs :D

## TODO features 

* html output (perhaps by running a one-page server in a go routine?)
* custom ignore folders/files
* make it easy to add new rules along with tests (perhaps with json, yaml, etc.)
* optimize all these regexes (maybe initialize them in an `init()` ?)

## TODO rules

- [ ] add a test that detects when .proto doesn't have mandatory structures? (or a specific test for .pb.go?)
- [ ] https://github.com/veorq/blueflower/blob/master/blueflower/constants.py
- [ ] https://github.com/veorq/blueflower
- [ ] mention blueflower
- [ ] the libgcrypt stuff I found
- [ ] ROCA tests https://blog.cr.yp.to/20171105-infineon.html
- [ ] debian keys test?
- [ ] check keysizes of every algorithm in certificates or pem keys

## TODO tests

* what open source project to test with unicornator?

