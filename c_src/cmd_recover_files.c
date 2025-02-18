#include <getopt.h>

#include "cmds.h"

#include "libbcachefs/dirent.h"
#include "libbcachefs/journal_io.h"
#include "libbcachefs/sb-members.h"
#include "libbcachefs/super.h"

static void recover_files_usage(void)
{
	puts("bcachefs recover-files - attempt to recover deleted files to a given target location\n"
	     "Usage: bcachefs recover-files [OPTION]... <devices>\n"
	     "\n"
	     "Options:\n"
	     "  -t, --target-dir      Target directory to place the files in.\n"
		 "                        Use a location on a different filesystem to prevent destroying the data.\n"
		 "  -s, --start-time      The start time (in Unix time) after which to recover data.\n"
	     "  -v, --verbose         Enable verbose mode for disk operations.\n"
	     "  -h, --help            Display this help and exit.\n"
	     "Report bugs to <linux-bcachefs@vger.kernel.org>");
}

static bool should_recover(struct jset *jset, u64 start_time)
{
	if (start_time == 0) {
		return true;
	}

	for_each_jset_entry_type(entry, jset, BCH_JSET_ENTRY_datetime) {
		struct jset_entry_datetime *datetime = container_of(entry, struct jset_entry_datetime, entry);
		if (le64_to_cpu(datetime->seconds) >= start_time) {
			return true;
		}
	}

	return false;
}

static inline bool entry_is_transaction_start(struct jset_entry *entry)
{
	return entry->type == BCH_JSET_ENTRY_log && !entry->level;
}

static bool is_transaction(struct jset_entry *entry, const char *transaction)
{
	struct jset_entry_log *log = container_of(entry, struct jset_entry_log, entry);
	unsigned msg_len_bytes = jset_entry_log_msg_bytes(log);
	return strncmp(transaction, log->d, msg_len_bytes) == 0;
}

static bool is_unlink_transaction(struct jset_entry *entry)
{
	return is_transaction(entry, "__bch2_unlink");
}

static bool is_inode_rm_transaction(struct jset_entry *entry)
{
	return is_transaction(entry, "bch2_inode_rm");
}

static int recover_unlink_data(struct jset_entry *entry, const char* target_dir)
{
	jset_entry_for_each_key(entry, key) {
		if (key->k.type != KEY_TYPE_dirent) {
			continue;
		}

		struct bkey_s_c s_c = bkey_i_to_s_c(key);
		struct bkey_s_c_dirent dirent = bkey_s_c_to_dirent(s_c);
		if (dirent.v->d_type != DT_REG) {
			continue;
		}

		printf("Found deleted filename record. Symlinking name to recovered inode...\n");

		struct qstr dname = bch2_dirent_get_name(dirent);
		size_t filenameSize = strlen(target_dir) + dname.len + 2;
		char filename[filenameSize];
		if (snprintf(filename, filenameSize, "%s/%s", target_dir, dname.name) < 0) {
			return -1;
		}

		size_t targetNameSize = 25;
		char targetName[targetNameSize];
		if (snprintf(targetName, targetNameSize, "./%llu", le64_to_cpu(dirent.v->d_inum)) < 0) {
			return -1;
		}

		if (symlink(targetName, filename) < 0) {
			printf("Failed to create helper symlink: %s\n", filename);
			return -1;
		}

		printf("Symlink created: %s -> %s\n", filename, targetName);
	}
	return 0;
}

static int recover_inode_data(struct jset_entry *entry, const char* target_dir, struct bch_fs *fs)
{
	jset_entry_for_each_key(entry, key) {
		if (key->k.type != KEY_TYPE_extent) {
			continue;
		}

		printf("Found deleted extent entry. Attempting read...\n");

		struct bkey_s_c s_c = bkey_i_to_s_c(key);
		struct extent_ptr_decoded pick;
		int rc = bch2_bkey_pick_read_device(fs, s_c, NULL, &pick, -1);
		if (rc < 0) {
			printf("Failed to pick source device for extent.\n");
			return rc;
		}

		struct bch_dev *dev = bch2_dev_get_ioref(fs, pick.ptr.dev, READ, BCH_DEV_READ_REF_io_read);
		if (!dev) {
			printf("Failed to get ioref for device.\n");
			return -BCH_ERR_device_offline;
		}

		// TODO: actually read extent data

		printf("Opening recovery file...\n");

		size_t filenameSize = strlen(target_dir) + 25;
		char filename[filenameSize];
		if (snprintf(filename, filenameSize, "%s/%llu", target_dir, le64_to_cpu(s_c.k->p.inode)) < 0) {
			return -1;
		}

		int fd = open(filename, O_RDWR|O_CREAT, 0600);
		if (fd < 0) {
			printf("Failed to open file: %s\n", filename);
			return -1;
		}

		// Size and Offset in extent represent 512 byte sectors amounts.
		// Offset denotes the /end/ within the file so calculate backwards using size.
		u64 offset = (le64_to_cpu(s_c.k->p.offset) - le32_to_cpu(s_c.k->size)) * 512;

		printf("File %s opened. Seeking to offset %llu to write extent data...\n", filename, offset);

		if (lseek(fd, offset, SEEK_SET) < 0) {
			printf("Failed to seek to offset %llu.\n", offset);
			return -1;
		}

		printf("Writing out extent data...\n");

		// TODO: write extent data to file
		//write(fd, ..., ...);
		close(fd);

		printf("Extent written to file.\n");
	}
	return 0;
}

static int do_recover_files(struct bch_fs *fs, const char* target_dir, u64 start_time)
{
	struct journal_replay *p, **_p;
	struct genradix_iter iter;

	genradix_for_each(&fs->journal_entries, iter, _p) {
		p = *_p;
		if (!p || !should_recover(&p->j, start_time)) {
			continue;
		}

		printf("Processing journal entry %llu for recovery...\n", le64_to_cpu(p->j.seq));

		bool processing_unlink_transaction = false;
		bool processing_inode_rm_transaction = false;
		for (struct jset_entry *entry = p->j.start; entry != vstruct_last(&p->j); entry = vstruct_next(entry)) {
			if (entry_is_transaction_start(entry)) {
				processing_unlink_transaction = is_unlink_transaction(entry);
				processing_inode_rm_transaction = is_inode_rm_transaction(entry);
				if (processing_unlink_transaction || processing_inode_rm_transaction) {
					printf("Found eligable transaction! Checking contents...\n");
				}
				continue;
			}

			if (entry->type != BCH_JSET_ENTRY_overwrite) {
				continue;
			}

			if (processing_unlink_transaction) {
				if (recover_unlink_data(entry, target_dir) < 0) {
					return -1;
				}
			}

			if (processing_inode_rm_transaction) {
				if (recover_inode_data(entry, target_dir, fs) < 0) {
					return -1;
				}
			}
		}
	}
	return 0;
}

int cmd_recover_files(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "target-dir", required_argument, NULL, 't' },
		{ "start-time", required_argument, NULL, 's' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL }
	};
	struct bch_opts opts = bch2_opts_empty();
	const char *target_dir = NULL;
	u64 start_time = 0;
	int opt;

	opt_set(opts, noexcl, true);
	opt_set(opts, nochanges, true);
	opt_set(opts, norecovery, true);
	opt_set(opts, read_only, true);
	opt_set(opts, degraded, BCH_DEGRADED_yes);
	opt_set(opts, retain_recovery_info, true);
	opt_set(opts, read_journal_only, true);
	opt_set(opts, read_entire_journal, true);

	while ((opt = getopt_long(argc, argv, "t:s:p:vh", longopts, NULL)) != -1)
		switch (opt) {
		case 't':
			target_dir = strdup(optarg);
			break;
		case 's':
			if (kstrtou64(optarg, 10, &start_time))
				die("error parsing start_time");
			break;
		case 'v':
			opt_set(opts, verbose, true);
			break;
		case 'h':
			recover_files_usage();
			exit(EXIT_SUCCESS);
		}
	args_shift(optind);

	if (!target_dir) {
		die("Please supply a target directory");
	}

	if (!argc) {
		die("Please supply device(s) to open");
	}

	darray_str devs = get_or_split_cmdline_devs(argc, argv);
	struct bch_fs *c = bch2_fs_open(devs.data, devs.nr, opts);
	if (IS_ERR(c)) {
		die("error opening %s: %s", argv[0], bch2_err_str(PTR_ERR(c)));
	}

	printf("Starting recovery...\n");
	int rc = do_recover_files(c, target_dir, start_time);
	if (rc < 0) {
		printf("Problem encountered during recovery. Aborted.\n");
	}

	bch2_fs_stop(c);
	return rc;
}
