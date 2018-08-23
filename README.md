# optee_rsa_example
This is an example of RSA encrypt/decrypt methods running on OP-TEE.

Below, you find the steps to setup the environment to run OPTEE on QEMU. These steps are available in the build page of the OPTEE github (https://github.com/OP-TEE/build).

To get and build OPTEE on QEMU, you have to follow the steps below:

1. Install the following packages:

    sudo apt-get install android-tools-adb android-tools-fastboot autoconf \
	automake bc bison build-essential cscope curl device-tree-compiler \
	expect flex ftp-upload gdisk iasl libattr1-dev libc6:i386 libcap-dev \
	libfdt-dev libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev \
	libpixman-1-dev libssl-dev libstdc++6:i386 libtool libz1:i386 make \
	mtools netcat python-crypto python-serial python-wand unzip uuid-dev \
	xdg-utils xterm xz-utils zlib1g-dev

2. Get the repo tool and make it executable:

    wget https://storage.googleapis.com/git-repo-downloads/repo
    chmod a+x repo

3. Create a directory for optee and enter inside it:

    mkdir optee
    cd optee

4. Get the source code:

    ./../repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
    ./../repo sync

5. Get the toolchains:

    cd build
    make toolchains

6. Build the solution:

    make

7. Run OPTEE on QEMU:

    make run

8. When the process stops, the QEMU console will be waiting. Just type c to continue. Two terminals will open: one with the "Rich OS" (Normal World) and another with the "Trusted OS" (Trusted World - OPTEE).

9. In the Rich OS (Normal World), enter "root" to login. You now can test the examples, running one of the following:

    hello_world
    aes
    hotp
    random

10. To run this RSA example, clone this GitHub repository in the optee/optee_examples folder, update the needed references according to the organization in your system and `make run`again. When this process finishes and you login in the normal world, you can run also the rsa application, just typing rsa.
