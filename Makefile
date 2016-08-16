all: BuseFS BuseFS_ll FormatBuseFS

BuseFS:
	gcc -Wall -Werror `pkg-config fuse3 --cflags --libs` BuseFS.c -o BuseFS

BuseFS_ll:
	gcc -Wall -Werror `pkg-config fuse3 --cflags --libs` BuseFS_lowlevel.c -o BuseFS_ll

FormatBuseFS: FormatBuseFS.c
	gcc -Wall -Werror FormatBuseFS.c -o FormatBuseFS

clean:
	rm -rf BuseFS
	rm -rf BuseFS_ll
	rm -rf FormatBuseFS
