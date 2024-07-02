if [ -e /dev/xpmem ]; then
    rmmod xpmem
fi
insmod "$1"
chmod 666 /dev/xpmem
sh -c "echo 1 > /proc/xpmem/debug_printk"
