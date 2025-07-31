#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here

    # deep clean
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper

    # default config
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig

    # build vmlinux
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all

    # modules (skip as per assignment instructions)
    #make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules

    # device tree
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs

    if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]
    then
        echo "Kernel build did not generate ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image" >&2
    fi



fi

echo "Adding the Image in outdir"
# there was no TODO here but I guess it's what they meant with the echo above
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}



echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p rootfs
cd rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys usr usr/bin usr/lib usr/sbin var var/log



cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
    git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox

    # deep clean
    make distclean

    # default config
    make defconfig



else
    cd busybox
fi

# TODO: Make and install busybox

# build
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}

# install
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install



cd "${OUTDIR}/rootfs"

echo "Library dependencies"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs

# path where to look for interpreter and libraries to copy on rootfs
# the binary used as reference should be at /some/path/bin
# the libraries should be at /some/path/aarch64-none-linux-gnu/libc
CROSS_COMPILE_PATH=$( dirname $( which ${CROSS_COMPILE}gcc ))/../${CROSS_COMPILE%-}/libc

# add interpreter
# parse output of readelf to extract the interpreter
# expected format of interpreter: /lib/ld-something.so.1
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter" \
    | while read -r interpreter_readelf_output_line
do
    interpreter=${interpreter_readelf_output_line##*: /}
    interpreter=${interpreter%]}

    echo "Copying interpreter $interpreter"
    cp ${CROSS_COMPILE_PATH}/${interpreter} ${OUTDIR}/rootfs/${interpreter}
done

# add libraries
# parse output of readelf to extract the libraries
# expected format of library: libm.so.1
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library" \
    | while read -r sharedlib_readelf_output_line
do
    sharedlib=${sharedlib_readelf_output_line##*: [}
    sharedlib=${sharedlib%]}

    echo "Copying library $sharedlib"
    cp ${CROSS_COMPILE_PATH}/lib64/${sharedlib} ${OUTDIR}/rootfs/lib64/${sharedlib}
done



# TODO: Make device nodes

# dev/null (major 1 minor 3)
if [ ! -c "${OUTDIR}/rootfs/dev/null" ]
then
    sudo mknod -m 666 "${OUTDIR}/rootfs/dev/null" c 1 3
fi

# console (major 5 minor 1)
if [ ! -c "${OUTDIR}/rootfs/dev/console" ]
then
    sudo mknod -m 666 "${OUTDIR}/rootfs/dev/console" c 5 1
fi

# tty (major 5 minor 0)
if [ ! -c "${OUTDIR}/rootfs/dev/tty" ]
then
    sudo mknod -m 666 "${OUTDIR}/rootfs/dev/tty" c 5 0
fi



# TODO: Clean and build the writer utility

cd "${FINDER_APP_DIR}"
make clean
make CROSS_COMPILE=${CROSS_COMPILE}



# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs

cp -r ${FINDER_APP_DIR}/writer "${OUTDIR}/rootfs/home"
cp -r ${FINDER_APP_DIR}/finder*.sh "${OUTDIR}/rootfs/home"
cp -r ${FINDER_APP_DIR}/autorun-qemu.sh "${OUTDIR}/rootfs/home"
mkdir -p "${OUTDIR}/rootfs/home/conf"
cp -r ${FINDER_APP_DIR}/conf/*.txt "${OUTDIR}/rootfs/home/conf"


# TODO: Chown the root directory

sudo chown -R root:root ${OUTDIR}/rootfs



# TODO: Create initramfs.cpio.gz

cd "${OUTDIR}/rootfs"

# create new cpio of the rootfs
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio

# compress cpio
cd ${OUTDIR}

gzip -f initramfs.cpio
