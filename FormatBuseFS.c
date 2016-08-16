#include "params.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#define REMAINING_LENGTH ((BITMAP_LENGTH*PAGE_SIZE)+(BITMAP_LENGTH*FILE_SIZE))

/*
 * Program that takes block device (/dev/sdX)
 * as an argument and formats the device
 * with Busefs
 */
static void print_usage(void)
{
	printf("./format <block device>\n");
	printf("example : ./format /dev/sdb\n");
}

static int write_superblock_to_disk(int fd, struct superblock *sb)
{
	int offset = 0, res = 0;
	char temp[INTEGER_BYTES_SIZE];

	/*Writing Check sum*/
	res = pwrite(fd, sb->checksum, FUSE_STRING_LENGTH, offset);
	if (res < 0 || res != FUSE_STRING_LENGTH) {
		perror("Block device write error\n");
		res = -1;
		goto writeout;
	}
	/*Writing Bit Map*/
	offset = offset + FUSE_STRING_LENGTH + DELIMETER_LENGTH;
	res = pwrite(fd, sb->bitmap, BITMAP_LENGTH, offset);
	if (res < 0 || res != BITMAP_LENGTH) {
		perror("Block device write error\n");
		res = -1;
		goto writeout;
	}
	/*Writing Metadata start location*/
	offset = offset + BITMAP_LENGTH + DELIMETER_LENGTH;
	sprintf(temp, "%d", sb->metadata_loc);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error\n");
		res = -1;
		goto writeout;
	}
	/*Writing Data start location*/
	offset = offset + INTEGER_BYTES_SIZE;
	sprintf(temp, "%d", sb->data_loc);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error\n");
		res = -1;
		goto writeout;
	}
	/*Writing Inode start location*/
	offset = offset + INTEGER_BYTES_SIZE;
	sprintf(temp, "%d", sb->inode_loc);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error\n");
		res = -1;
		goto writeout;
	}
	res = 0;
writeout:
	return res;
}

int main(int argc, char *argv[])
{
	char *device;
	int fd, res = 0;
	struct superblock *sb;

	if (argc != 2) {
		print_usage();
		return -1;
	}
	device = argv[1];
	fd = open(device, O_RDWR);
	if (fd < 0) {
		perror("Block device open error\n");
		return -1;
	}
	/*Constructing the Super Block*/
	printf("Constructing the Super Block of BuseFS\n");
	sb = (struct superblock *)malloc(sizeof(struct superblock));
	strncpy(sb->checksum, FUSE_STRING, FUSE_STRING_LENGTH);
	sb->checksum[FUSE_STRING_LENGTH] = DELIMETER;
	strncpy(sb->bitmap, BITMAP_STRING, BITMAP_LENGTH);
	sb->bitmap[BITMAP_LENGTH] = DELIMETER;
	sb->metadata_loc = METADATA_START_LOCATION;
	sb->data_loc = DATA_START_LOCATION;
	sb->inode_loc = INODE_START_LOCATION;
	sb->inode_list = NULL;

	/*Write Super Block to disk*/
	res = write_superblock_to_disk(fd, sb);
	if (res) {
		printf("Format failed\n");
		goto out1;
	}

	printf("Format Done Succefully\n");
	res = 0;
out1:
	free(sb);
	close(fd);
	return res;
}
