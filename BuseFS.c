#define FUSE_USE_VERSION 30
#define _XOPEN_SOURCE 500
#include "params.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <fuse.h>
#include <stdbool.h>

#define FILENAME_LENGTH (PAGE_SIZE)
#define PRIVATE_DATA ((struct myPrivate *)fuse_get_context()->private_data)
#define START_BYTES_LENGTH (FUSE_STRING_LENGTH)

/*
  command to compile
  "gcc -Wall blockFileSystem.c `pkg-config fuse3 --cflags --libs` -o blockFS"
*/
/*
 * Layout:
 * 1. First 4 bytes is "FUSE",
 * 2. Next 16 bytes is a Bit Map representing the files present,
 * 3. Next 16*4096 bytes is saved for file names,
 * 4. Next 16*1MB is reserved for file data.
*/


static int debug;
char debugmsg[FILENAME_LENGTH];
char tmpspace[FILENAME_LENGTH];
char tmpfilePath[FILENAME_LENGTH];

static void print_usage(void)
{
	printf("USAGE      : ./simpleFS ");
	printf("<fuseMountOptions> <blockDev> <mountDir> [-d]\n");
	printf("<blockDev> : The block device ");
	printf("where the Real File system exists\n");
	printf("<mountDir> : Mount Directory on ");
	printf("to which the F/S should be mounted\n");
	printf("[-d]	   : optional argument to start ");
	printf("debug mode (where debug ");
	printf("messages are written to blockFS.log)\n");
	printf("Example    : ./blockFS -f /dev/sdb mountDir/ -d\n");
	printf("After Succesfull Mount the content ");
	printf("from rootDir will be seen in mountDir\n");
}

struct myPrivate {
	struct superblock *sb;
	int block_dev_fd;
	FILE *debug_log_fd;
};

static void log_message(const char *text, ...)
{
	FILE *fp;
	va_list ap;

	if (!debug)
		return;
	fp = PRIVATE_DATA->debug_log_fd;
	va_start(ap, text);
	vfprintf(fp, text, ap);
	va_end(ap);
}

static void free_filepath(char *temp)
{
	/*make 4096 bytes to NULL*/
	memset(temp, '\0', sizeof(char)*FILENAME_LENGTH);
}

static int read_superblock_from_disk(int fd, struct superblock *sb)
{
	int offset = 0, res = 0;
	char temp[INTEGER_BYTES_SIZE];

	/*Read checksum*/
	res = pread(fd, sb->checksum, FUSE_STRING_LENGTH
					+DELIMETER_LENGTH, offset);
	if (res < 0 || res != FUSE_STRING_LENGTH+DELIMETER_LENGTH) {
		perror("Block device read error");
		res = -1;
		goto readout;
	}
	offset = offset + FUSE_STRING_LENGTH + DELIMETER_LENGTH;
	/*Read Bit Map*/
	res = pread(fd, sb->bitmap, BITMAP_LENGTH+DELIMETER_LENGTH, offset);
	if (res < 0 || res != BITMAP_LENGTH+DELIMETER_LENGTH) {
		perror("Block device read error");
		res = -1;
		goto readout;
	}
	offset = offset + BITMAP_LENGTH + DELIMETER_LENGTH;
	/*Read Metadata Location*/
	res = pread(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device read error");
		res = -1;
		goto readout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	sb->metadata_loc = atoi(temp);
	/*Read Data Location*/
	res = pread(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device read error");
		res = -1;
		goto readout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	sb->data_loc = atoi(temp);
	/*Read Inode Location*/
	res = pread(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device read error");
		res = -1;
		goto readout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	sb->inode_loc = atoi(temp);
	res = 0;
readout:
	return res;
}

static int write_metadata_to_disk(int fd, int _offset,
				struct metadata_node *md)
{
	int res = 0, offset;
	char temp[INTEGER_BYTES_SIZE];

	offset = _offset;
	/*Write File name*/
	res = pwrite(fd, md->filename, sizeof(md->filename), offset);
	if (res < 0 || res != sizeof(md->filename)) {
		perror("Block device write error");
		res = -1;
		goto writemetadataout;
	}
	offset = offset + FILENAME_LENGTH;
	/*Write Inode number*/
	sprintf(temp, "%d", md->inode_no);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error");
		res = -1;
		goto writemetadataout;
	}
	res = 0;
writemetadataout:
	return res;
}

static int read_inode_from_disk(int fd, int _offset, struct inode *ino)
{
	int res = 0, offset;
	char temp[INTEGER_BYTES_SIZE];

	offset = _offset;
	/*read data location*/
	res = pread(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device read error");
		res = -1;
		goto inodereadout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	ino->data_loc = atoi(temp);
	/*read start location*/
	res = pread(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device read error");
		res = -1;
		goto inodereadout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	ino->start_loc = atoi(temp);
	/*read end location*/
	res = pread(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device read error");
		res = -1;
		goto inodereadout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	ino->end_loc = atoi(temp);
	/*read size*/
	res = pread(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device read error");
		res = -1;
		goto inodereadout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	ino->size = atoi(temp);
	res = 0;
inodereadout:
	return res;
}


static int write_inode_to_disk(int fd, int _offset, struct inode *ino)
{
	int res = 0, offset;
	char temp[INTEGER_BYTES_SIZE];

	offset = _offset;
	/*Write data loc*/
	sprintf(temp, "%d", ino->data_loc);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error");
		res = -1;
		goto writeinodeout;
	}
	offset = offset + INTEGER_BYTES_SIZE;

	/*Write start location*/
	sprintf(temp, "%d", ino->start_loc);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error");
		res = -1;
		goto writeinodeout;
	}
	offset = offset + INTEGER_BYTES_SIZE;

	/*Write end location*/
	sprintf(temp, "%d", ino->end_loc);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error");
		res = -1;
		goto writeinodeout;
	}
	offset = offset + INTEGER_BYTES_SIZE;

	/*Write size*/
	sprintf(temp, "%d", ino->size);
	res = pwrite(fd, temp, INTEGER_BYTES_SIZE, offset);
	if (res < 0 || res != INTEGER_BYTES_SIZE) {
		perror("Block device write error");
		res = -1;
		goto writeinodeout;
	}
	offset = offset + INTEGER_BYTES_SIZE;
	res = 0;

writeinodeout:
	return res;
}

static int write_superblock_bitmap_to_disk(int fd, struct superblock *sb)
{
	int res = 0, offset = 0;

	offset = FUSE_STRING_LENGTH + DELIMETER_LENGTH;
	/*write bit map to disk*/
	res = pwrite(fd, sb->bitmap, BITMAP_LENGTH, offset);
	if (res < 0 || res != BITMAP_LENGTH) {
		perror("Block device write error");
		res = -1;
		goto bitmapwriteout;
	}
	res = 0;
bitmapwriteout:
	return res;
}

static int check_block_dev_assign_to_private(struct myPrivate *userdata,
					char *blockDev)
{
	int fd, res = 0;
	char temp[START_BYTES_LENGTH];

	fd = open(blockDev, O_RDWR);
	if (fd < 0) {
		perror("Block device open error");
		res = -1;
		goto checkout;
	}
//	printf("The FD of block device : %d\n", fd);
	res = pread(fd, temp, FUSE_STRING_LENGTH, 0);
	if (res < 0 || res != FUSE_STRING_LENGTH) {
		perror("Block device read error");
		res = -1;
		goto checkout;
	}
	if (strcmp(temp, FUSE_STRING)) {
		printf("The block device is not formated with FUSE\n");
		res = -1;
		goto checkout;
	} else {
		printf("The block device is compatable ");
		printf("with FUSE(Succesfull)\n");
		res = 0;
	}
	res = read_superblock_from_disk(fd, userdata->sb);
	if (res) {
		printf("Error: Reading Superblock from disk\n");
		res = -1;
		goto checkout;
	}
	userdata->block_dev_fd = fd;
checkout:
	return res;
}

static void free_myprivate(struct myPrivate *userdata)
{
	if (userdata->block_dev_fd != -1)
		close(userdata->block_dev_fd);
	if (userdata->debug_log_fd)
		fclose(userdata->debug_log_fd);
	if (userdata->sb)
		free(userdata->sb);
	if (userdata)
		free(userdata);
}

static int return_file_index(const char *path)
{
	/*Read the Bit Map*/
	char *file_path = NULL;
	int fd, res = 0, i;
	struct superblock *sb;

	fd = PRIVATE_DATA->block_dev_fd;
	sb = PRIVATE_DATA->sb;

	sprintf(debugmsg, "temp value : %s\n", sb->bitmap);
	log_message(debugmsg);

	for (i = 0; i < BITMAP_LENGTH; i++) {
		if ((sb->bitmap)[i] == '1') {
			/*Read filenames from block device
			*starting from (20 + i*4096) and 4096 bytes at a time*/
			file_path = tmpfilePath;
			res = pread(fd, file_path, FILENAME_LENGTH,
				(METADATA_START_LOCATION)
				+ (i*(METADATA_LENGTH)));
			if (res < 0) {
				perror("Block device read error\n");
				res = 0;
				goto checkout;
			}
			if (!strcmp(path, file_path)) {
				log_message("File Found\n");
				res = i;
				goto checkout;
			}
			free_filepath(file_path);
		}
	}
	res = -1;
checkout:
	if (file_path)
		free_filepath(file_path);
	return res;
}

static int blockfs_getattr(const char *path, struct stat *statbuf)
{
	int fd, res = 0, pos;
	struct inode *ino = NULL;

	log_message("Get Attr called\n");
	sprintf(debugmsg, "Path : %s\n", path);
	log_message(debugmsg);
	printf("getattr called with path : %s\n", path);
	if (!strcmp(path, "/")) {
		/*Assigning Dummy Values*/
		statbuf->st_dev = 64770;
		statbuf->st_ino = 134348040;
		statbuf->st_mode = 16893;
		statbuf->st_nlink = 1;
		statbuf->st_uid = 0;
		statbuf->st_gid = 0;
		statbuf->st_rdev = 0;
		statbuf->st_size = 4096;
		statbuf->st_atime = 1453192917;
		statbuf->st_mtime = 1453193173;
		statbuf->st_ctime = 1453193173;
		statbuf->st_blksize = 4096;
		statbuf->st_blocks = 0;
	} else {
		pos = return_file_index(path);
		if (pos != -1) {
			fd = PRIVATE_DATA->block_dev_fd;
			ino = (struct inode *)malloc(sizeof(struct inode));
			/*Load Inode from disk*/
			res = read_inode_from_disk(fd, INODE_START_LOCATION +
						(pos*INODE_LENGTH), ino);
			if (res) {
				perror("inode read error");
				goto getattrout;
			}
			statbuf->st_dev = 64770;
			statbuf->st_ino = 134348040;
			statbuf->st_mode = 33204;
			statbuf->st_nlink = 1;
			statbuf->st_uid = 0;
			statbuf->st_gid = 0;
			statbuf->st_rdev = 0;
			statbuf->st_size = ino->size;
			statbuf->st_atime = 1453192917;
			statbuf->st_mtime = 1453193173;
			statbuf->st_ctime = 1453193173;
			statbuf->st_blksize = 4096;
			statbuf->st_blocks = 0;
		} else
			return -ENOENT;
	}
getattrout:
	if (ino)
		free(ino);
	return res;
}

static int blockfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi,
			enum fuse_readdir_flags flags)
{
	char *file_path = NULL;
	int fd, res = 0, i;
	struct superblock *sb;

	printf("Readdir called on path : %s\n", path);
	log_message("Read Dir called\n");
	sprintf(debugmsg, "Path : %s\n", path);
	log_message(debugmsg);

	if (strcmp(path, "/"))
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	/*Read the 16 bytes of bit map and get the file names*/
	fd = PRIVATE_DATA->block_dev_fd;
	sb = PRIVATE_DATA->sb;

	sprintf(debugmsg, "Bit Map : %s\n", sb->bitmap);
	log_message(debugmsg);

	for (i = 0; i < BITMAP_LENGTH; i++) {
		if ((sb->bitmap)[i] == '1') {
			/*Read filenames from block device
			*starting from (20 + i*4096) and 4096 bytes at a time*/
			file_path = tmpfilePath;
			res = pread(fd, file_path, FILENAME_LENGTH,
				(METADATA_START_LOCATION)
				+ (i*(METADATA_LENGTH)));
			sprintf(debugmsg,
				"File path inside Readdir : %s : %d\n",
				file_path, (int)strlen(file_path));
			log_message(debugmsg);
			if (res < 0) {
				perror("Block device read error\n");
				res = -1;
				goto readdirout;
			}
			filler(buf, file_path+1, NULL, 0, 0);
			free_filepath(file_path);
		}
	}
	res = 0;
readdirout:
	if (file_path)
		free_filepath(file_path);
	return res;
}

static int blockfs_create(const char *path,
			mode_t mode, struct fuse_file_info *fi)
{
	int res = 0, empty_pos = -1, fd, i;
	struct superblock *sb;
	struct metadata_node *md = NULL;
	struct inode *ino = NULL;

	printf("create called with path : %s\n", path);
	log_message("Create Called\n");
	sprintf(debugmsg, "Path : %s\n", path);
	log_message(debugmsg);

	/* Read the 16 bytes of bit Map to find the empty place */
	fd = PRIVATE_DATA->block_dev_fd;
	sb = PRIVATE_DATA->sb;

	for (i = 0; i < BITMAP_LENGTH; i++) {
		if ((sb->bitmap)[i] == '0') {
			empty_pos = i;
			break;
		}
	}

	if (empty_pos == -1) {
		log_message("No Empty Position found(Disk Full)\n");
		res = -ENOSPC;
		goto createout;
	}

	/*Construct metadata*/
	md = (struct metadata_node *)malloc(sizeof(struct metadata_node));
	strncpy(md->filename, path, strlen(path));
	md->filename[strlen(path)] = '\0';
	md->inode_no = (INODE_START_LOCATION)+(empty_pos*INODE_LENGTH);

	/*Construct inode*/
	ino = (struct inode *)malloc(sizeof(struct inode));
	ino->data_loc = DATA_START_LOCATION + (empty_pos*FILE_SIZE);
	ino->start_loc = ino->end_loc = ino->data_loc;
	ino->size = (ino->end_loc) - (ino->start_loc);


	/*Write Metadata to file*/
	res = write_metadata_to_disk(fd, (METADATA_START_LOCATION +
					(empty_pos * METADATA_LENGTH)), md);
	if (res) {
		log_message("Metadata Write Error\n");
		res = -1;
		goto createout;
	}
	/*Write Inode to file*/
	res = write_inode_to_disk(fd, (INODE_START_LOCATION +
					(empty_pos * INODE_LENGTH)), ino);
	if (res) {
		log_message("Inode Write Error\n");
		res = -1;
		goto createout;
	}

	/*Update the Bit in SB and write*/
	(sb->bitmap)[empty_pos] = '1';
	res = write_superblock_bitmap_to_disk(fd, sb);
	if (res) {
		log_message("Superblock Bitmap Write Error\n");
		res = -1;
		goto createout;
	}
	/*Assigning position in bitmap as file handle*/
	fi->fh = empty_pos;
	res = 0;
createout:
	if (md)
		free(md);
	if (ino)
		free(ino);
	return res;
}


static int blockfs_utimens(const char *path, const struct timespec tv[2])
{
	return 0;
}



static int blockfs_open(const char *path, struct fuse_file_info *fi)
{
	int fd, res = 0;

	printf("Open called with path : %s\n", path);
	log_message("Open Called\n");
	fd = return_file_index(path);
	if (fd < 0) {
		res = -ENOENT;
		goto openout;
	}
	fi->fh = fd;
	res = 0;
openout:
	return res;
}

static int blockfs_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	int block_fd, res, data_loc;
	struct inode *ino = NULL;

	printf("Read called on path : %s and size : %d from offset : %d\n",
						path, (int)size, (int)offset);
	sprintf(debugmsg, "Read Called at offset : %d\n", (int)offset);
	log_message(debugmsg);

	block_fd = PRIVATE_DATA->block_dev_fd;
	/*load the inode*/
	ino = (struct inode *)malloc(sizeof(struct inode));
	res = read_inode_from_disk(block_fd, (INODE_START_LOCATION
					+(fi->fh * INODE_LENGTH)), ino);
	if (res) {
		perror("Inode read error\n");
		res = -EINVAL;
		goto readout;
	}
	/*check offset lies with in*/
	if ((ino->start_loc + offset) < ino->end_loc)
		log_message("offset within range\n");
	else {
		log_message("offset outof range range\n");
		res = 0;
		goto readout;
	}
	/*check how much to read*/
	if ((ino->start_loc+offset+size) < ino->end_loc) {
		log_message("read size within range\n");
	} else {
		log_message("read size out of range\n");
		size = ino->end_loc - (ino->start_loc + offset);
	}
	data_loc = offset + ((DATA_START_LOCATION)
			+((fi->fh)*(FILE_SIZE)));
	res = pread(block_fd, buf, size, data_loc);
	if (res < 0 || res != size) {
		log_message("Block device read error\n");
		res = -EINVAL;
	}
	printf("read returning : %d\n", res);
readout:
	if (ino)
		free(ino);
	return res;
}

static int blockfs_write(const char *path, const char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	int block_fd, res, data_loc, written, prev_end;
	bool sizechanged = false;
	struct inode *ino = NULL;

	printf("Write called on path : %s of size : %d from offset : %d\n",
						path, (int)size, (int)offset);
	sprintf(debugmsg, "Write Called at offset : %d\n", (int)offset);
	log_message(debugmsg);

	block_fd = PRIVATE_DATA->block_dev_fd;
	/*read inode*/
	ino = (struct inode *)malloc(sizeof(struct inode));
	res = read_inode_from_disk(block_fd, (INODE_START_LOCATION
					+(fi->fh * INODE_LENGTH)), ino);
	if (res) {
		perror("Inode read error\n");
		res = -EINVAL;
		goto writeout;
	}
	/*Check for size limit*/
	if ((ino->start_loc + offset + size) <= (ino->start_loc + FILE_SIZE))
		log_message("Perfectly Alright to write\n");
	else {
		log_message("File Size limit exceed\n");
		res = -ENOSPC;
		goto writeout;
	}
	/*update endpointer*/
	if ((ino->start_loc + offset + size) <= (ino->end_loc))
		log_message("No change in end pointer\n");
	else {
		prev_end = ino->end_loc;
		ino->end_loc = ino->start_loc + offset + size;
		sizechanged = true;
	}
	/*update the size*/
	if (sizechanged) {
		ino->size = ino->end_loc - ino->start_loc;
		/*write zeros from prev_end of size (ino->end_loc - prev_end)*/
		data_loc = prev_end;
		printf("Zeros writing from : %d of size : %d\n", data_loc,
						(ino->end_loc - prev_end));
		memset(tmpspace, 0, (ino->end_loc - prev_end));
		res = pwrite(block_fd, tmpspace, (ino->end_loc - prev_end),
								data_loc);
		if (res < 0 || res != (ino->end_loc - prev_end)) {
			log_message("Block device write error\n");
			res = -EINVAL;
			goto writeout;
		}
		log_message("zeros written to the extended location\n");
	}
	/*Write data*/
	/*Finding the Data Location*/
	data_loc = offset + ((DATA_START_LOCATION)
			+((fi->fh)*(FILE_SIZE)));
	res = pwrite(block_fd, buf, size, data_loc);
	if (res < 0 || res != size) {
		log_message("Block device write error\n");
		res = -EINVAL;
		goto writeout;
	}
	written = res;
	/*write inode back to disk*/
	res = write_inode_to_disk(block_fd, (INODE_START_LOCATION
					+(fi->fh * INODE_LENGTH)), ino);
	if (res) {
		perror("Inode write error\n");
		res = -EINVAL;
		/*Date is written but user doesn't know*/
		goto writeout;
	}
	res = written;
	printf("write returning %d\n", res);
writeout:
	if (ino)
		free(ino);
	return res;
}

static int blockfs_truncate(const char *path, off_t newsize)
{
	int res = 0, pos, fd;
	struct inode *ino = NULL;

	log_message("Truncate Called\n");
	printf("Truncate called with path : %s and new size : %d\n",
							path, (int)newsize);
	pos = return_file_index(path);
	printf("Postion of file returned : %d\n", pos);
	if (pos == -1) {
		res = -ENOENT;
		goto truncateout;
	} else {
		/*load the inode*/
		fd = PRIVATE_DATA->block_dev_fd;
		ino = (struct inode *)malloc(sizeof(struct inode));
		res = read_inode_from_disk(fd, INODE_START_LOCATION +
						(pos*INODE_LENGTH), ino);
		if (res) {
			perror("Inode load error\n");
			res = -EINVAL;
			goto truncateout;
		}
		printf("Inode loaded succesfully\n");
		ino->size = (int)newsize;
		ino->end_loc = (ino->start_loc) + (ino->size);
		/*write inode to disk*/
		res = write_inode_to_disk(fd, INODE_START_LOCATION +
						(pos*INODE_LENGTH), ino);
		if (res) {
			perror("Inode write error\n");
			res = -EINVAL;
			goto truncateout;
		}
		printf("inode wrote succesfully\n");
	}
	res = 0;
truncateout:
	if (ino)
		free(ino);
	return res;
}

static int blockfs_release(const char *path, struct fuse_file_info *fi)
{
	printf("Release Called on path : %s\n", path);
	log_message("Release Called\n");
	/*Closing and making fh to -1*/
	fi->fh = -1;
	return 0;
}

static int blockfs_access(const char *path, int mask)
{
	printf("Access called on path : %s\n", path);
	/*Return success in all cases*/
	return 0;
}

static int blockfs_unlink(const char *path)
{
	int block_fd, res = 0, bit_loc;
	struct superblock *sb;

	printf("Unlink method called on : %s\n", path);
	sprintf(debugmsg, "Unlink method called on : %s\n", path);
	log_message(debugmsg);

	block_fd = PRIVATE_DATA->block_dev_fd;
	sb = PRIVATE_DATA->sb;
	bit_loc = return_file_index(path);
	/*Put 0 at this bit loc*/
	(sb->bitmap)[bit_loc] = '0';
	res = write_superblock_bitmap_to_disk(block_fd, sb);
	if (res) {
		log_message("Superblock Bitmap Write Error\n");
		res = -1;
		goto unlinkout;
	}
	res = 0;
unlinkout:
	return res;
}

static FILE *log_open(void)
{
	FILE *logfile;

	logfile = fopen("BuseFS.log", "w");
	if (!logfile) {
		perror("logfile");
		exit(EXIT_FAILURE);
	}
	return logfile;
}


struct fuse_operations blockfs_operations = {
	.getattr  = blockfs_getattr,
	.create   = blockfs_create,
	.utimens  = blockfs_utimens,
	.open     = blockfs_open,
	.truncate = blockfs_truncate,
	.release  = blockfs_release,
	.read     = blockfs_read,
	.write    = blockfs_write,
	.readdir  = blockfs_readdir,
	.access   = blockfs_access,
	.unlink   = blockfs_unlink
};


int main(int argc, char **argv)
{
	int res = 0;
	char *blockDev = NULL;
	struct myPrivate *userdata;

	if (argc < 3) {
		print_usage();
		return -1;
	}

	if (!strcmp(argv[argc-1], "-d"))
		debug = 1;
	else
		debug = 0;

	if (debug)
		blockDev = argv[argc - 3];
	else
		blockDev = argv[argc - 2];
	if (blockDev) {
		userdata = (struct myPrivate *)malloc(sizeof(*userdata));
		userdata->sb = (struct superblock *)malloc(sizeof(
							struct superblock));
		userdata->block_dev_fd = -1;
		userdata->debug_log_fd = NULL;
		res = check_block_dev_assign_to_private(userdata, blockDev);
	} else {
		res = -1;
		goto mainout;
	}
	if (res) {
		printf("Could not be mounted\n");
		goto mainout;
	}
	userdata->sb->inode_list = NULL;
	if (debug)
		userdata->debug_log_fd = log_open();
	else
		userdata->debug_log_fd = NULL;
	if (debug) {
		argv[argc-3] = argv[argc-2];
		argv[argc-2] = NULL;
		argv[argc-1] = NULL;
		argc = argc-2;
	} else {
		argv[argc-2] = argv[argc-1];
		argv[argc-1] = NULL;
		argc--;
	}
	res = fuse_main(argc, argv, &blockfs_operations, userdata);
mainout:
	free_myprivate(userdata);
	return res;
}
