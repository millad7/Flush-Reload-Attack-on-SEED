# Flush+Reload Attacks on SEED

This repository is an implementation of a flush-reload side channel attack on SEED encryption. 

This attack should be performed on a virtual machine dedicated for the execution of this program. So the safety of your
host machine will not be affected in any way.

This attack targets OpenSSL's SEED implementation. In order to perform this attack on your own machine,
follow the steps outlined below.

Flush+Reload is a powerful access-driven cache attack in which the attacker leverages a security weakness in the X86 processor architecture to extract the private data of the victim. This attack can be mounted in a cross-core setting, where the memory de-duplication is enabled and several users are sharing the same physical machine. In this work, for the first time, we demonstrate that SEED implementation running inside the victim VM is vulnerable against the Flush+Reload attacks and the attacker can recover the keys of this encryption. SEED is a standard encryption algorithm that was developed by the Korea Information Security Agency (KISA) and has been used for confidential services in the Republic of Korea. This work demonstrates that the attacker can retrieve the secret keys of SEED in 3 minutes in the native setup and 4 minutes in the cross-VM setup by performing the Flush+Reload technique. Our experimental results show that common implementation of this standard cipher is vulnerable to Flush+Reload attack in both native and cross-VM settings.

## Experiment setup

Native setup: In this setup, the attacker and the victim are running on the same physical machine in Ubuntu 16.04.

Cross-VM setup: In this setup, the attacker and the victim are running on two distinct VMs (VMware Esxi 5.5.0) in two different cores. We
also assume that the co-resident problem has been solved and the attacker process and the victim process are performed on a shared physical machine.

## OpenSSL Installation

Trusted Versions of OpenSSL can be found at: https://www.openssl.org//. This attack will work for most
versions, but the specific version I used was version openssl-1.1.0f. After downloading the OpenSSL source, go to
the Downloads folder and unzip with:

    tar -xvf openssl-1.1.0f.tar.gz

Now we need to configure OpenSSL to use its t-table c implementation as opposed to the assembly implementation default.
OpenSSL also needs to be configured with debug symbols and specified to use a shared object as opposed to an .a library.
For the appropriate configuration, run:

    cd ~/Downloads/openssl-1.1.0f
    ./config -d shared no-asm no-hw
    
For the selected version: 1.1.0f, this configuration will install OpenSSL in the /usr/local/ directory. The configuration parameters specify
that we allow for debug symbols (used to locate T-table locations), create a shared object. To proceed with the install, run:

    sudo make
    sudo make install_sw

## Compile and run the programs

Native: 

The command for compiling and running the seed.cpp file is:

g++ seed.cpp -o seed -I/usr/local/include/ssl -L/usr/local/lib -lcrypto
    
./seed

Cross-VM:

The command for compiling and running the server.c file is:

g++ server.c -o server -I/usr/local/include/ssl -L/usr/local/lib -lcrypto
    
./server

The command for compiling the client.c file is:

g++ client.c -o client -I/usr/local/include/ssl -L/usr/local/lib -lcrypto

./client











