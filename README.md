ccminer with mtp support
========================
djm34 2017-2018

donation addresses:

	BTC: 1NENYmxwZGHsKFmyjTc5WferTn5VTFb7Ze

	XZC: aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5

Based on Christian Buchner's &amp; Christian H.'s CUDA project and tpruvot@github.


Building on windows
-------------------

Required: msvc2015 and cuda 9.2 or higher (cuda 10.1 prefered)
Dependencies for windows are included in compat directory, using a different version of msvc will most likely require to recompile those libraries.

In order to build ccminer, choose "Release" and "x64" (this version won't work with win32)
Then click "generate"

Building on Linux (tested on Ubuntu 16.04)
------------------------------------------


	* sudo apt-get update && sudo apt-get -y dist-upgrade
	* sudo apt-get -y install gcc g++ build-essential automake linux-headers-$(uname -r) git gawk libcurl4-openssl-dev libjansson-dev xorg libc++-dev libgmp-dev python-dev

	* Installing CUDA 10.1 and compatible drivers from nvidia website and not from ubuntu package is usually easier
	
	* Compiling ccminner:

	./autogen.sh
	./configure
	./make


About source code dependencies for windows
------------------------------------------

This project requires some libraries to be built :

- OpenSSL (prebuilt for win)

- Curl (prebuilt for win)

- pthreads (prebuilt for win)

The tree now contains recent prebuilt openssl and curl .lib for both x86 and x64 platforms (windows).

To rebuild them, you need to clone this repository and its submodules :
    git clone https://github.com/peters/curl-for-windows.git compat/curl-for-windows


Running ccminer with mtp and requirement
----------------------------------------

mtp requires 4.4Gb of vram, hence cards with less than 4.5Gb of vram won't work.
The program uses also around 500Mb and 4.4xCard Number of swap/virtual memory

*Instruction to mine on zcoin wallet (solo mining)

command line structure

ccminer -a mtp -o  http://127.0.0.1:rpcport  -u rpcuser -p rpcpassword --coinbase-addr zcoin-address  -d listofcards  --no-getwork  

Example (RUN-ZCOIN-MTP.cmd)

ccminer -a mtp -o  http://127.0.0.1:8382  -u djm34 -p password --coinbase-addr aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5 --no-getwork -d 0,1,2 -i 22


zcoin wallet should also be run with "server=1" option and "rpcport,rpcuser,rpcpassword" should match those of zcoin.conf


*Instruction for mining on pool: 
ccminer -a mtp -o stratum+tcp://zcoin.mintpond.com:3000 -u aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5.worker   -p 0,strict,verbose,d=500 -i 20 











