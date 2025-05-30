#!/bin/bash
# Copyright 2016 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# create-image.sh creates a minimal Debian Linux image suitable for syzkaller.

set -eux

# Create a minimal Debian distribution in a directory.
DIR=chroot
PREINSTALL_PKGS=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default

# If ADD_PACKAGE is not defined as an external environment variable, use our default packages
if [ -z ${ADD_PACKAGE+x} ]; then
    ADD_PACKAGE="make,sysbench,git,vim,tmux,usbutils,tcpdump,net-tools"
fi

# Variables affected by options
RELEASE=bookworm
FEATURE=minimal
SEEK=2047
PERF=false

# Display help function
display_help() {
    echo "Usage: $0 [option...] " >&2
    echo
    echo "   -d, --distribution         Set on which debian distribution to create"
    echo "   -f, --feature              Check what packages to install in the image, options are minimal, full"
    echo "   -s, --size                 Image size (MB), default 2048 (2G)"
    echo "   -h, --help                 Display help message"
    echo "   -p, --add-perf             Add perf support with this option enabled. Please set envrionment variable \$KERNEL at first"
    echo
}

while true; do
    if [ $# -eq 0 ];then
	echo $#
	break
    fi
    case "$1" in
        -h | --help)
            set +x
            display_help
            exit 0
            ;;
        -d | --distribution)
	    RELEASE=$2
            shift 2
            ;;
        -f | --feature)
	    FEATURE=$2
            shift 2
            ;;
        -s | --seek)
	    SEEK=$(($2 - 1))
            shift 2
            ;;
        -p | --add-perf)
	    PERF=true
            shift 1
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            exit 1
            ;;
        *)  # No more options
            break
            ;;
    esac
done

# Double check KERNEL when PERF is enabled
if [ $PERF = "true" ] && [ -z ${KERNEL+x} ]; then
    echo "Please set KERNEL environment variable when PERF is enabled"
    exit 1
fi

# If full feature is chosen, install more packages
if [ $FEATURE = "full" ]; then
    PREINSTALL_PKGS=$PREINSTALL_PKGS","$ADD_PACKAGE
fi

sudo rm -rf $DIR
mkdir -p $DIR
sudo debootstrap --include=$PREINSTALL_PKGS $RELEASE $DIR

# Set some defaults and enable promtless ssh to the machine for root.
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $DIR/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $DIR/etc/network/interfaces
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo "kernel.printk = 7 4 1 3" | sudo tee -a $DIR/etc/sysctl.conf
echo 'debug.exception-trace = 0' | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_enable = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_kallsyms = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_harden = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.softlockup_all_cpu_backtrace = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.kptr_restrict = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.watchdog_thresh = 60" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a $DIR/etc/sysctl.conf
echo -en "127.0.0.1\tlocalhost\n" | sudo tee $DIR/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $DIR/etc/resolve.conf
echo "pwnctf" | sudo tee $DIR/etc/hostname

# Add perf support
if [ $PERF = "true" ]; then
    cp -r $KERNEL $DIR/tmp/
    sudo chroot $DIR /bin/bash -c "apt-get update; apt-get install -y flex bison python-dev libelf-dev libunwind8-dev libaudit-dev libslang2-dev libperl-dev binutils-dev liblzma-dev libnuma-dev"
    sudo chroot $DIR /bin/bash -c "cd /tmp/linux/tools/perf/; make"
    sudo chroot $DIR /bin/bash -c "cp /tmp/linux/tools/perf/perf /usr/bin/"
    rm -r $DIR/tmp/linux
fi

# create a default user called scada
echo "scada::1000:1000:scada:/home/scada:/bin/bash" | sudo tee -a $DIR/etc/passwd
echo "scada:x:1000:" | sudo tee -a $DIR/etc/group
sudo mkdir -p $DIR/home/scada/.ssh
cat $RELEASE.id_rsa.pub | sudo tee $DIR/home/scada/.ssh/authorized_keys
sudo chown -R 1000:1000 $DIR/home/scada

# install python3
sudo chroot $DIR /bin/bash -c "apt-get update"
sudo chroot $DIR /bin/bash -c "apt-get install -y python3 && ln -s /usr/bin/python3 /usr/bin/python"

# create ssh key and save it
ssh-keygen -f $RELEASE.id_rsa -t rsa -N ''
sudo mkdir -p $DIR/home/scada/.ssh/
cat $RELEASE.id_rsa.pub | sudo tee $DIR/home/scada/.ssh/authorized_keys

# Copy in and setup the vulnerable kernel module
sudo cp ../safectl.ko $DIR/root/safectl.ko
echo "@reboot root insmod /root/safectl.ko && chmod 777 /dev/safetyctl; chmod 700 /root/flag.txt; chmod 777 /proc/kallsyms" | sudo tee -a $DIR/etc/crontab
echo "@reboot root echo 0 | sudo tee /proc/sys/kernel/kptr_restrict" | sudo tee -a $DIR/etc/crontab
echo "@reboot root echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid" | sudo tee -a $DIR/etc/crontab
echo "@reboot root echo \"7\" | sudo tee /proc/sys/kernel/printk" | sudo tee -a $DIR/etc/crontab
echo "@reboot root /sbin/sysctl -w kernel.dmesg_restrict=0" | sudo tee -a $DIR/etc/crontab

# Copy in the flag
sudo cp ../flag.txt $DIR/root/flag.txt

# Build a disk image
dd if=/dev/zero of=$RELEASE.img bs=1M seek=$SEEK count=1
sudo mkfs.ext4 -F $RELEASE.img
sudo mkdir -p /mnt/$DIR
sudo mount -o loop $RELEASE.img /mnt/$DIR
sudo cp -a $DIR/. /mnt/$DIR/.
sudo umount /mnt/$DIR

# cleanup
sudo rmdir /mnt/$DIR
sudo rm -rf $DIR
