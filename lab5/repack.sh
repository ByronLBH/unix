cd ./rootfs
find . -print | cpio -ov -H newc | bzip2 > ../dist/rootfs.cpio.bz2