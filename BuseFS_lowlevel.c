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
#include <fuse_lowlevel.h>
#include <stdbool.h>

#define START_BYTES_LENGTH (FUSE_STRING_LENGTH)
#define FILENAME_LENGTH (PAGE_SIZE)

static int debug;
char debugmsg[FILENAME_LENGTH];
char tmpspace[FILENAME_LENGTH];
char tmpfilePath[FILENAME_LENGTH];

static void print_usage(void)
{
        printf("USAGE      : ./BuseFS_ll ");
        printf("<fuseMountOptions> <blockDev> <mountDir> [-d]\n");
        printf("<blockDev> : The block device ");
        printf("where the Real File system exists\n");
        printf("<mountDir> : Mount Directory on ");
        printf("to which the F/S should be mounted\n");
        printf("[-d]       : optional argument to start ");
        printf("debug mode (where debug ");
        printf("messages are written to blockFS_ll.log)\n");
        printf("Example    : ./blockFS_ll -f /dev/sdb mountDir/ -d\n");
        printf("After Succesfull Mount the content ");
        printf("from rootDir will be seen in mountDir\n");
}

struct myPrivate {
        struct superblock *sb;
        int block_dev_fd;
        FILE *debug_log_fd;
};

static void free_filepath(char *temp)
{
        /*make 4096 bytes to NULL*/
        memset(temp, '\0', sizeof(char)*FILENAME_LENGTH);
}

static struct superblock *return_superblock(fuse_req_t req)
{
        return ((struct myPrivate *)fuse_req_userdata(req))->sb;
}

static int return_blockdev_fd(fuse_req_t req)
{
	return ((struct myPrivate *)fuse_req_userdata(req))->block_dev_fd;
}


static void log_message(const char *text, ...)
{
        FILE *fp;
        va_list ap;

        if (!debug)
                return;
        fp = NULL;
        va_start(ap, text);
        vfprintf(fp, text, ap);
        va_end(ap);
}

static void fuse_free_buf(struct fuse_bufvec *buf)
{
        if (buf != NULL) {
                size_t i;

                for (i = 0; i < buf->count; i++)
                        free(buf->buf[i].mem);
                free(buf);
        }
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

static int return_file_index(fuse_req_t req, const char *path)
{
        /*Read the Bit Map*/
        char *file_path = NULL;
        int fd, res = 0, i;
        struct superblock *sb;

        fd = return_blockdev_fd(req);
        sb = return_superblock(req);
        sprintf(debugmsg, "temp value : %s\n", sb->bitmap);
        log_message(debugmsg);

        for (i = 0; i < BITMAP_LENGTH; i++) {
                if ((sb->bitmap)[i] == '1') {
                        /*Read filenames from block device
 *                         *starting from (20 + i*4096) and 4096 bytes at a time*/
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
				printf("File found is : %s\n", file_path);
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

static int return_inode_index(fuse_req_t req, fuse_ino_t ino)
{
        /*Read the Bit Map*/
        int fd, res = 0, i;
	char temp[INTEGER_BYTES_SIZE];
        struct superblock *sb;

        fd = return_blockdev_fd(req);
        sb = return_superblock(req);

        sprintf(debugmsg, "temp value : %s\n", sb->bitmap);
        log_message(debugmsg);

        for (i = 0; i < BITMAP_LENGTH; i++) {
                if ((sb->bitmap)[i] == '1') {
                        /*Read inodes from block device
                    	*starting from (20 + i*4096) + 4096 
			and 16 bytes at a time*/
                        res = pread(fd, temp, INTEGER_BYTES_SIZE,
                                (METADATA_START_LOCATION)
                                + (i*(METADATA_LENGTH)) + FILENAME_LENGTH);
                        if (res < 0) {
                                perror("Block device read error\n");
                                res = 0;
                                goto checkout;
                        }
                        if (atoi(temp) == ino) {
                                log_message("Inode Found\n");
                                res = i;
                                goto checkout;
                        }
                }
        }
        res = -1;
checkout:
        return res;
}

static void free_myprivate(struct myPrivate *userdata)
{
	printf("Freeing the userdata\n");
        if (userdata->block_dev_fd != -1)
                close(userdata->block_dev_fd);
        if (userdata->debug_log_fd)
                fclose(userdata->debug_log_fd);
        if (userdata->sb)
                free(userdata->sb);
        if (userdata)
                free(userdata);
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

static void busefs_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
        printf("Lookup Called on : %s\n", name);
	struct fuse_entry_param e;
	struct inode *ino = NULL;
	int res, pos, fd;
	
	if (parent != 1)
		fuse_reply_err(req, ENOENT);
	else  {
		pos = return_file_index(req, name);
		printf("File position : %d\n", pos);
		if (pos != -1) {
			fd = return_blockdev_fd(req);
			ino = (struct inode *)malloc(sizeof(struct inode));
                        /*Load Inode from disk*/
                        res = read_inode_from_disk(fd, INODE_START_LOCATION +
                                                (pos*INODE_LENGTH), ino);
                        if (res) {
                                perror("inode read error");
                                if (ino)
					free(ino);
				fuse_reply_err(req, ENOENT);
				return ;
                        }
			memset(&e, 0, sizeof(e));
                	e.ino = (INODE_START_LOCATION)+(pos*INODE_LENGTH);
                	e.attr_timeout = 1.0;
                	e.entry_timeout = 1.0;
                	e.attr.st_ino = e.ino;
			e.attr.st_mode = 33204;
                        e.attr.st_nlink = 1;
                        e.attr.st_size = ino->size;
                        e.attr.st_atime = 1453192917;
                        e.attr.st_mtime = 1453193173;
                        e.attr.st_ctime = 1453193173;
                        e.attr.st_blksize = 4096;
                        e.attr.st_blocks = 0;
                        if (ino)
                                free(ino);
                	fuse_reply_entry(req, &e);
		} else
			fuse_reply_err(req, ENOENT);
	}	
}

static void busefs_ll_getattr(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi)
{
	printf("Get attr Called on inode : %d\n", (int)ino);
	int pos, fd, res = 0;
	struct superblock *sb;
	struct inode *inode = NULL;
	struct stat statbuf;

	sb = return_superblock(req);
	printf("Checksum from sb : %s\n", sb->checksum);
	printf("Bit map from sb : %s\n", sb->bitmap);
	printf("Inode number : %d\n", (int)ino);
	if (ino == 1) { /*equal to comparing as "/" */
		memset(&statbuf, 0, sizeof(statbuf));
                statbuf.st_ino = ino;
                statbuf.st_mode = S_IFDIR | 0755;
                statbuf.st_nlink = 1;
		statbuf.st_size = 4096;
                statbuf.st_atime = 1453192917;
                statbuf.st_mtime = 1453193173;
                statbuf.st_ctime = 1453193173;
                statbuf.st_blksize = 4096;
                statbuf.st_blocks = 0;
		fuse_reply_attr(req, &statbuf, 1.0);
	} else {
		pos = return_inode_index(req, ino);
		if (pos != -1) {
			fd = return_blockdev_fd(req);
			 inode = (struct inode *)malloc(sizeof(struct inode));
                        /*Load Inode from disk*/
                        res = read_inode_from_disk(fd, INODE_START_LOCATION +
                                                (pos*INODE_LENGTH), inode);
                        if (res) {
                                perror("inode read error");
                                fuse_reply_err(req, ENOENT);
				if (inode)
					free(inode);
				return ;
                        }
			memset(&statbuf, 0, sizeof(statbuf));
                	statbuf.st_ino = ino;
                	statbuf.st_mode = S_IFREG | 0444;
                	statbuf.st_nlink = 1;
                	statbuf.st_size = inode->size;
                	statbuf.st_atime = 1453192917;
                	statbuf.st_mtime = 1453193173;
                	statbuf.st_ctime = 1453193173;
               	 	statbuf.st_blksize = 4096;
                	statbuf.st_blocks = 0;
			if (inode)
				free(inode);
                	fuse_reply_attr(req, &statbuf, 1.0);
			
		} else
			fuse_reply_err(req, ENOENT);
	}
}

struct dirbuf {
        char *p;
        size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
                       fuse_ino_t ino)
{
        printf("Dir Buff add Called with file name : %s and inode : %d\n", name, (int)ino);
        struct stat stbuf;
        size_t oldsize = b->size;
        b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
        b->p = (char *) realloc(b->p, b->size);
        memset(&stbuf, 0, sizeof(stbuf));
        stbuf.st_ino = ino;
        fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
                          b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
                             off_t off, size_t maxsize)
{
        if (off < bufsize)
                return fuse_reply_buf(req, buf + off,
                                      min(bufsize - off, maxsize));
        else
                return fuse_reply_buf(req, NULL, 0);
}


static void busefs_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                             off_t off, struct fuse_file_info *fi)
{
        printf("Readdir Called\n");
	char *file_path = NULL;
	char temp[INTEGER_BYTES_SIZE];
	int i, fd, res = 0, inode;
	struct superblock *sb;
	struct dirbuf b;
	
	if (ino != 1)
		fuse_reply_err(req, ENOTDIR);
	else {
                memset(&b, 0, sizeof(b));
                dirbuf_add(req, &b, ".", 1);
                dirbuf_add(req, &b, "..", 1);
		sb = return_superblock(req);
		fd = return_blockdev_fd(req);
		for (i = 0; i < BITMAP_LENGTH; i++) {
                	if ((sb->bitmap)[i] == '1') {
                        	/*Read filenames, inode numbers from block device
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
					if (file_path)
						free_filepath(file_path);
                                	fuse_reply_err(req, ENOTDIR);
					return ;
                        	}
				res = pread(fd, temp, INTEGER_BYTES_SIZE,
                                                (METADATA_START_LOCATION)
                                                + (i*(METADATA_LENGTH)) + FILENAME_LENGTH);
				if (res < 0 || res != INTEGER_BYTES_SIZE) {
                			perror("Block device read error");
                			if (file_path)
                                                free_filepath(file_path);
                                        fuse_reply_err(req, ENOTDIR);
					return ;
        			}
				inode = atoi(temp);
				dirbuf_add(req, &b, file_path, inode);
                        	free_filepath(file_path);
                	}
        	}
		reply_buf_limited(req, b.p, b.size, off, size);
                free(b.p);
	}
}

static void busefs_ll_open(fuse_req_t req, fuse_ino_t ino,
                          struct fuse_file_info *fi)
{
        printf("Open Called\n");
	int fd;
	fd = return_inode_index(req, ino);
	if (fd < 0) {
		fuse_reply_err(req, ENOENT);
		return ;
	}
	fi->fh = fd;
	fuse_reply_open(req, fi);
}

static void busefs_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
                          off_t off, struct fuse_file_info *fi)
{
        printf("Read Called\n");
	int block_fd, res, data_loc;
        struct inode *inode = NULL;
	struct fuse_bufvec *buf;
	void *mem;

        buf = malloc(sizeof(struct fuse_bufvec));
        if (buf == NULL) {
        	fuse_reply_err(req, ENOMEM);
		return ;
	}

        mem = malloc(size);
        if (mem == NULL) {
       		free(buf);
                fuse_reply_err(req, ENOMEM);
		return ;
        }
        *buf = FUSE_BUFVEC_INIT(size);
        (buf->buf[0]).mem = mem;
	
	printf("Read called on inode : %d and size : %d from offset : %d\n",
                                                (int)ino, (int)size, (int)off);
        sprintf(debugmsg, "Read Called at offset : %d\n", (int)off);
        log_message(debugmsg);

        block_fd = return_blockdev_fd(req);
        /*load the inode*/
        inode = (struct inode *)malloc(sizeof(struct inode));
        res = read_inode_from_disk(block_fd, (INODE_START_LOCATION
                                        +(fi->fh * INODE_LENGTH)), inode);
        if (res) {
                perror("Inode read error\n");
		free(buf);
		free(mem);
		free(inode);
                fuse_reply_err(req, EINVAL);
                return ;
        }
        /*check offset lies with in*/
        if ((inode->start_loc + off) < inode->end_loc)
                log_message("offset within range\n");
        else {
                log_message("offset outof range range\n");
                buf->buf[0].size = 0;
		fuse_reply_data(req, buf, FUSE_BUF_SPLICE_MOVE);
	        fuse_free_buf(buf);
		return ;
        }
        /*check how much to read*/
        if ((inode->start_loc+off+size) < inode->end_loc) {
                log_message("read size within range\n");
        } else {
                log_message("read size out of range\n");
                size = inode->end_loc - (inode->start_loc + off);
        }
        data_loc = off + ((DATA_START_LOCATION)
                        	+((fi->fh)*(FILE_SIZE)));
        res = pread(block_fd, mem, size, data_loc);
        if (res < 0 || res != size) {
                log_message("Block device read error\n");
		free(buf);
                free(mem);
                free(inode);
                fuse_reply_err(req, EINVAL);
		return ;
        }
        printf("read returning : %d\n", res);
	if (res > 0)
		buf->buf[0].size = res;
	free(inode);
	fuse_reply_data(req, buf, FUSE_BUF_SPLICE_MOVE);
	fuse_free_buf(buf);
}

static void busefs_ll_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                        mode_t mode, struct fuse_file_info *fi)
{
	int res = 0, empty_pos = -1, fd, i;
	struct fuse_entry_param e;
        struct superblock *sb;
        struct metadata_node *md = NULL;
        struct inode *ino = NULL;

        printf("create called with path : %s\n", name);
        log_message("Create Called\n");
        sprintf(debugmsg, "Path : %s\n", name);
        log_message(debugmsg);

        /* Read the 16 bytes of bit Map to find the empty place */
        fd = return_blockdev_fd(req);
        sb = return_superblock(req);

        for (i = 0; i < BITMAP_LENGTH; i++) {
                if ((sb->bitmap)[i] == '0') {
                        empty_pos = i;
                        break;
                }
        }

        if (empty_pos == -1) {
                log_message("No Empty Position found(Disk Full)\n");
		fuse_reply_err(req, ENOSPC);
                goto createout;
        }

        /*Construct metadata*/
        md = (struct metadata_node *)malloc(sizeof(struct metadata_node));
        strncpy(md->filename, name, strlen(name));
        md->filename[strlen(name)] = '\0';
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
                fuse_reply_err(req, EINVAL);
                goto createout;
        }
        /*Write Inode to file*/
        res = write_inode_to_disk(fd, (INODE_START_LOCATION +
                                        (empty_pos * INODE_LENGTH)), ino);
        if (res) {
                log_message("Inode Write Error\n");
                fuse_reply_err(req, EINVAL);
                goto createout;
        }

        /*Update the Bit in SB and write*/
        (sb->bitmap)[empty_pos] = '1';
        res = write_superblock_bitmap_to_disk(fd, sb);
        if (res) {
                log_message("Superblock Bitmap Write Error\n");
                fuse_reply_err(req, EINVAL);
                goto createout;
        }
        /*Assigning position in bitmap as file handle*/
        fi->fh = empty_pos;
	memset(&e, 0, sizeof(e));
        e.ino = md->inode_no;
        e.attr_timeout 	= 1.0;
       	e.entry_timeout = 1.0;
      	e.attr.st_ino 	= e.ino;
        e.attr.st_mode 	= 33204;
        e.attr.st_nlink = 1;
        e.attr.st_size 	= ino->size;
       	e.attr.st_atime = 1453192917;
       	e.attr.st_mtime = 1453193173;
       	e.attr.st_ctime = 1453193173;
        e.attr.st_blksize = 4096;
        e.attr.st_blocks  = 0;
	fuse_reply_create(req, &e, fi);
createout:
        if (md)
                free(md);
        if (ino)
                free(ino);
        return ;
}

static void busefs_ll_release(fuse_req_t req, fuse_ino_t ino,
                         struct fuse_file_info *fi)
{
	printf("released called\n");
	fi->fh = -1;
	fuse_reply_err(req, 0);
}

static void busefs_ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                         int to_set, struct fuse_file_info *fi)
{
	printf("set attr called\n");
	int pos, fd, res = 0;
	bool truncate_called = false;
	struct stat statbuf;
	struct inode *inode = NULL;

	if (to_set & FUSE_SET_ATTR_SIZE) {
		/*Truncate called(update size)*/
		printf("Truncate called\n");
		pos = return_inode_index(req, ino);
		printf("Postion of file returned : %d\n", pos);
        	if (pos == -1) {
			fuse_reply_err(req, ENOENT);
			return ;
		} else {
			fd = return_blockdev_fd(req);
                	inode = (struct inode *)malloc(sizeof(struct inode));
                	res = read_inode_from_disk(fd, INODE_START_LOCATION +
                                                (pos*INODE_LENGTH), inode);
                	if (res) {
                        	perror("Inode load error\n");
				fuse_reply_err(req, ENOENT);
                        	return ;
                	}
                	printf("Inode loaded succesfully\n");
                	inode->size = attr->st_size;
                	inode->end_loc = (inode->start_loc) + (inode->size);
                	/*write inode to disk*/
                	res = write_inode_to_disk(fd, INODE_START_LOCATION +
                                                (pos*INODE_LENGTH), inode);
                	if (res) {
                        	perror("Inode write error\n");
                        	fuse_reply_err(req, ENOENT);
                        	return ;
                	}
                	printf("inode wrote succesfully\n");
			truncate_called = true;
		}
	}
	if ((to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) ==
                    (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		printf("Update time called(Doing Nothing)\n");
       	}
	if (!truncate_called) {
		/*load the inode*/
		pos = return_inode_index(req, ino);
                fd = return_blockdev_fd(req);
                inode = (struct inode *)malloc(sizeof(struct inode));
                res = read_inode_from_disk(fd, INODE_START_LOCATION +
                                                (pos*INODE_LENGTH), inode);
                if (res) {
               		perror("inode read error");
                        fuse_reply_err(req, ENOENT);
                        if (inode)
                        	free(inode);
                        return ;
               }
	}
	memset(&statbuf, 0, sizeof(statbuf));
	statbuf.st_ino = ino;
	statbuf.st_mode = S_IFREG | 0444;
	statbuf.st_nlink = 1;
	statbuf.st_size = inode->size;
        statbuf.st_atime = 1453192917;
        statbuf.st_mtime = 1453193173;
        statbuf.st_ctime = 1453193173;
        statbuf.st_blksize = 4096;
        statbuf.st_blocks = 0;
        if (inode)
        	free(inode);
	fuse_reply_attr(req, &statbuf, 1.0);
}


static void busefs_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                       	size_t size, off_t off, struct fuse_file_info *fi)
{
	printf("write called\n");
	int block_fd, res, data_loc, written, prev_end;
        bool sizechanged = false;
        struct inode *inode = NULL;

        printf("Write called on path : %d of size : %d from offset : %d\n",
                                                (int)ino, (int)size, (int)off);
        sprintf(debugmsg, "Write Called at offset : %d\n", (int)off);
        log_message(debugmsg);

        block_fd = return_blockdev_fd(req);
        /*read inode*/
        inode = (struct inode *)malloc(sizeof(struct inode));
        res = read_inode_from_disk(block_fd, (INODE_START_LOCATION
                                        +(fi->fh * INODE_LENGTH)), inode);
        if (res) {
                perror("Inode read error\n");
		free(inode);
                fuse_reply_err(req, EINVAL);
                return ;
        }
        /*Check for size limit*/
        if ((inode->start_loc + off + size) <= (inode->start_loc + FILE_SIZE))
                log_message("Perfectly Alright to write\n");
        else {
                log_message("File Size limit exceed\n");
		free(inode);
                fuse_reply_err(req, ENOSPC);
                return ;
        }
        /*update endpointer*/
        if ((inode->start_loc + off + size) <= (inode->end_loc))
                log_message("No change in end pointer\n");
        else {
                prev_end = inode->end_loc;
                inode->end_loc = inode->start_loc + off + size;
                sizechanged = true;
        }
        /*update the size*/
        if (sizechanged) {
                inode->size = inode->end_loc - inode->start_loc;
                /*write zeros from prev_end of size (ino->end_loc - prev_end)*/
                data_loc = prev_end;
                printf("Zeros writing from : %d of size : %d\n", data_loc,
                                                (inode->end_loc - prev_end));
                memset(tmpspace, 0, (inode->end_loc - prev_end));
                res = pwrite(block_fd, tmpspace, (inode->end_loc - prev_end),
                                                                data_loc);
                if (res < 0 || res != (inode->end_loc - prev_end)) {
                        log_message("Block device write error\n");
			free(inode);
                        fuse_reply_err(req, EINVAL);
                        return ;
                }
                log_message("zeros written to the extended location\n");
        }
        /*Write data*/
        /*Finding the Data Location*/
        data_loc = off + ((DATA_START_LOCATION)
                        	+((fi->fh)*(FILE_SIZE)));
        res = pwrite(block_fd, buf, size, data_loc);
        if (res < 0 || res != size) {
                log_message("Block device write error\n");
		free(inode);
                fuse_reply_err(req, EINVAL);
                return ;
        }
        written = res;
        /*write inode back to disk*/
        res = write_inode_to_disk(block_fd, (INODE_START_LOCATION
                                        +(fi->fh * INODE_LENGTH)), inode);
        if (res) {
                perror("Inode write error\n");
		free(inode);
                fuse_reply_err(req, EINVAL);
                /*Date is written but user doesn't know*/
                return ;
        }
        res = written;
        printf("write returning %d\n", res);
        if (inode)
		free(inode);
	fuse_reply_write(req, res);
}

static void busefs_ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	int block_fd, res = 0, bit_loc;
        struct superblock *sb;

        printf("Unlink method called on : %s\n", name);
        sprintf(debugmsg, "Unlink method called on : %s\n", name);
        log_message(debugmsg);
	if (parent != 1) {
		fuse_reply_err(req, ENOENT);
		return ;
	}
        block_fd = return_blockdev_fd(req);
        sb = return_superblock(req);
        bit_loc = return_file_index(req, name);
        /*Put 0 at this bit loc*/
        (sb->bitmap)[bit_loc] = '0';
        res = write_superblock_bitmap_to_disk(block_fd, sb);
        if (res) {
                log_message("Superblock Bitmap Write Error\n");
                fuse_reply_err(req, EINVAL);
                return ;
        }
        res = 0;
        fuse_reply_err(req, res);
}


static struct fuse_lowlevel_ops hello_ll_oper = {
        .lookup         = busefs_ll_lookup,
        .getattr        = busefs_ll_getattr,
	.setattr	= busefs_ll_setattr,
        .readdir        = busefs_ll_readdir,
	.create		= busefs_ll_create,
        .open           = busefs_ll_open,
        .read           = busefs_ll_read,
	.write		= busefs_ll_write,
	.release	= busefs_ll_release,
	.unlink		= busefs_ll_unlink
};


int main(int argc, char *argv[])
{
	int res = 0, err = 0;
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
	printf("Main method Called\n");
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        struct fuse_chan *ch;
        char *mountpoint;
	res = fuse_parse_cmdline(&args, &mountpoint, NULL, NULL);
	if (res != -1) {
		printf("mountpoint : %s\n", mountpoint);
		printf("result value : %d\n", res);
		ch = fuse_mount(mountpoint, &args);
		if (ch) {
			printf("Mounted Successfully\n");
			struct fuse_session *se;
			se = fuse_lowlevel_new(&args, &hello_ll_oper,
						sizeof(hello_ll_oper), userdata);
			if (se) {
                        	if (fuse_set_signal_handlers(se) != -1) {
                                	fuse_session_add_chan(se, ch);
                                	/* Block until ctrl+c or fusermount -u */
                                	err = fuse_session_loop(se);
					printf("loop value returned : %d\n", err);
                                	fuse_remove_signal_handlers(se);
                                	fuse_session_remove_chan(ch);
                        	}
                        	fuse_session_destroy(se);
                	}
			printf("Unmounting before exit\n");
			fuse_unmount(mountpoint, ch);
		}
	}
	fuse_opt_free_args(&args);
mainout:
	free_myprivate(userdata);
	return 0;
}
