#include <getopt.h>

#include "cmds.h"

#include "libbcachefs/dirent.h"
#include "libbcachefs/io_read.h"
#include "libbcachefs/io_write.h"
#include "libbcachefs/journal_io.h"
#include "libbcachefs/sb-members.h"
#include "libbcachefs/super.h"

struct recover_settings {
	char *target_dir;
	u64 start_time;
	u64 end_time;
	bool ignore_csum;
	bool zero_fill;
	bool use_last;
	bool verbose;
	u64 extents_total;
	u64 extents_written;
	u64 extents_failed;
	u64 extents_csum;
	u64 extents_decompress;
	u64 files_names;
	u64 files_inodes;
};

struct recover_context {
	u64 inode;
	u64 size;
	u64 offset;
	void *data;
	struct bio *bio;
	struct bkey_i *key;
	struct bch_io_failures *failed;
	bool failed_csum;
	bool failed_decompress;
};

static void recover_files_usage(void)
{
	puts("bcachefs recover-files - Attempt to recover deleted files using journal information\n"
	     "Usage: bcachefs recover-files [OPTION]... <devices>\n"
	     "\n"
	     "Options:\n"
	     "  -t, --target-dir      Target directory to place the recovered files in. USE A LOCATION ON A DIFFERENT FILESYSTEM!\n"
	     "                        Fail to do so and risk destroying the data you're trying to recover!\n"
	     "  -s, --start-time      The time (in Unix time) after which deleted data should be recovered.\n"
	     "  -e, --end-time        The time (in Unix time) before which deleted data should be recovered.\n"
	     "  -i, --ignore-csum     Ignore checksum failures and accept the data as-is.\n"
	     "  -z, --zero-fill       Zero fill extent data if it can not (reliably) be read instead of bailing out.\n"
	     "  -l, --use-last        Write out last read extent data if it can not (reliably) be read instead of bailing out.\n"
	     "  -v, --verbose         Enable verbose mode for disk operations.\n"
	     "  -h, --help            Display this help and exit.\n"
	     "Report bugs to <linux-bcachefs@vger.kernel.org>");
}

static inline int verbose(struct recover_settings *settings, const char *fmt, ...) {
	int rc = 0;
	if (settings->verbose) {
		va_list args;
		va_start(args, fmt);
		rc = vprintf(fmt, args);
		va_end(args);
	}
	return rc;
}

static bool should_recover(struct recover_settings *settings, struct jset *jset)
{
	if (settings->start_time == 0 && settings->end_time == 0) {
		return true;
	}

	for_each_jset_entry_type(entry, jset, BCH_JSET_ENTRY_datetime) {
		struct jset_entry_datetime *datetime = container_of(entry, struct jset_entry_datetime, entry);
		u64 time = le64_to_cpu(datetime->seconds);
		// There's only 1 datetime entry per jset so we can directly return.
		return settings->start_time <= time && time <= settings->end_time;
	}

	return false;
}

static inline bool entry_is_transaction_start(struct jset_entry *entry)
{
	return entry->type == BCH_JSET_ENTRY_log && !entry->level;
}

static bool is_transaction(struct jset_entry *entry, char *transaction)
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

static int recover_unlink_details(struct recover_settings *settings, struct bkey_i *key)
{
	if (key->k.type != KEY_TYPE_dirent) {
		return 0;
	}

	struct bkey_s_c s_c = bkey_i_to_s_c(key);
	struct bkey_s_c_dirent dirent = bkey_s_c_to_dirent(s_c);
	if (dirent.v->d_type != DT_REG) {
		return 0;
	}

	verbose(settings, "Found deleted filename record. Symlinking name to recovered inode...\n");

	struct qstr dname = bch2_dirent_get_name(dirent);
	size_t filenameSize = strlen(settings->target_dir) + dname.len + 2;
	char filename[filenameSize];
	if (snprintf(filename, filenameSize, "%s/%s", settings->target_dir, dname.name) < 0) {
		return -1;
	}

	size_t targetNameSize = 25;
	char targetName[targetNameSize];
	if (snprintf(targetName, targetNameSize, "./%llu", le64_to_cpu(dirent.v->d_inum)) < 0) {
		return -1;
	}

	if (symlink(targetName, filename) < 0) {
		if (errno == EEXIST) {
			verbose(settings, "%s already exists. Skipping symlink creation.\n", filename);
			goto done;
		} else {
			printf("ERROR: failed to create symlink %s: %d\n", filename, errno);
			return -1;
		}
	}

	verbose(settings, "Symlink created: %s -> %s\n", filename, targetName);

done:
	settings->files_names++;
	return 0;
}

static int write_to_recovery_file(struct recover_settings *settings, struct recover_context *ctx)
{
	verbose(settings, "Opening recovery file...\n");

	size_t filenameSize = strlen(settings->target_dir) + 25;
	char filename[filenameSize];
	if (snprintf(filename, filenameSize, "%s/%llu", settings->target_dir, ctx->inode) < 0) {
		return -1;
	}

	int fd = open(filename, O_RDWR|O_CREAT, 0600);
	if (fd < 0) {
		printf("ERROR: failed to open target file %s: %d\n", filename, errno);
		return -1;
	}

	verbose(settings, "File %s opened. Seeking to offset %llu...\n", filename, ctx->offset);

	if (lseek(fd, ctx->offset, SEEK_SET) < 0) {
		printf("ERROR: failed to seek to offset %llu in %s: %d.\n", ctx->offset, filename, errno);
		close(fd);
		return -1;
	}

	verbose(settings, "Writing out %llu bytes of extent data...\n", ctx->size);

	ssize_t written = write(fd, ctx->data, ctx->size);
	if (written != ctx->size) {
		printf("ERROR: failed to write extent data to %s. Wrote: %lu, expected: %llu, errno: %d\n",
			filename, written, ctx->size, errno);
		close(fd);
		return -1;
	}

	close(fd);

	verbose(settings, "Extent written to file.\n");

	settings->extents_written++;
	return 0;
}

static int recovery_read_endio(struct recover_settings *settings, struct recover_context *ctx,
	struct bch_fs *fs, struct bio *read_bio, struct extent_ptr_decoded *pick)
{
	struct bio *orig = ctx->bio;
	struct bch_io_failures *failed = ctx->failed;
	struct bkey_i *key = ctx->key;

	struct nonce nonce = extent_nonce(key->k.bversion, pick->crc);

	if (orig != read_bio) {
		read_bio->bi_iter.bi_size = pick->crc.compressed_size << 9;
		read_bio->bi_iter.bi_idx = 0;
		read_bio->bi_iter.bi_bvec_done = 0;
	}

	verbose(settings, "Verifying checksum...\n");
	struct bch_csum csum = bch2_checksum_bio(fs, pick->crc.csum_type, nonce, read_bio);
	ctx->failed_csum = bch2_crc_cmp(csum, pick->crc.csum);
	if (ctx->failed_csum) {
		if (settings->verbose) {
			struct printbuf buf = PRINTBUF;
			bch2_csum_err_msg(&buf, pick->crc.csum_type, pick->crc.csum, csum);
			printf("%s\n", buf.buf);
			printbuf_exit(&buf);
		}

		if (!settings->ignore_csum) {
			goto retry;
		}
	}

	if (crc_is_compressed(pick->crc)) {
		assert(orig != read_bio);

		if (bch2_encrypt_bio(fs, pick->crc.csum_type, nonce, read_bio)) {
			goto retry;
		}

		verbose(settings, "Decompressing extent...\n");
		ctx->failed_decompress = bch2_bio_uncompress(fs, read_bio, orig, orig->bi_iter, pick->crc);
		if (ctx->failed_decompress) {
			printf("Failed to decompress extent.\n");
			goto retry;
		}
		bch2_bio_free_pages_pool(fs, read_bio);
		bio_put(read_bio);
	} else {
		/* don't need to decrypt the entire bio: */
		nonce = nonce_add(nonce, pick->crc.offset << 9);
		bio_advance(read_bio, pick->crc.offset << 9);

		if (bch2_encrypt_bio(fs, pick->crc.csum_type, nonce, read_bio)) {
			goto retry;
		}
	}
	return 0;

retry:
	bch2_mark_io_failure(failed, pick, ctx->failed_csum);
	if (orig != read_bio) {
		bch2_bio_free_pages_pool(fs, read_bio);
		bio_put(read_bio);
	}
	return failed->nr;
}

static int recovery_read_extent(struct recover_settings *settings, struct recover_context *ctx, struct bch_fs *fs)
{
	struct bio *orig = ctx->bio;
	struct bch_io_failures *failed = ctx->failed;
	struct bkey_i *key = ctx->key;

	struct bkey_s_c s_c = bkey_i_to_s_c(key);

	if (bkey_extent_is_inline_data(&key->k)) {
		unsigned bytes = min_t(unsigned, orig->bi_iter.bi_size, bkey_inline_data_bytes(&key->k));
		swap(orig->bi_iter.bi_size, bytes);
		memcpy_to_bio(orig, orig->bi_iter, bkey_inline_data_p(s_c));
		swap(orig->bi_iter.bi_size, bytes);
		bio_advance_iter(orig, &orig->bi_iter, bytes);
		zero_fill_bio_iter(orig, orig->bi_iter);
		return 0;
	}

	struct extent_ptr_decoded pick;
	if (bch2_bkey_pick_read_device(fs, s_c, failed, &pick, -1) < 0) {
		settings->extents_failed++;
		if (ctx->failed_csum) {
			settings->extents_csum++;
		}
		if (ctx->failed_decompress) {
			settings->extents_decompress++;
		}

		if (settings->zero_fill) {
			verbose(settings, "Zero-filling...\n");
			zero_fill_bio_iter(orig, orig->bi_iter);
			return 0;
		} else if (failed->nr > 0 && settings->use_last) {
			verbose(settings, "Using last read extent data...\n");
			return 0;
		}

		printf("ERROR: no device to read from.\n");
		return -1;
	}

	verbose(settings, "Reading from device %d...\n", pick.ptr.dev);

	struct bio *read_bio = NULL;
	if (crc_is_compressed(pick.crc)) {
		verbose(settings, "Compressed extent. Bouncing read to decompress...\n");
		unsigned sectors = pick.crc.compressed_size;
		read_bio = bio_alloc_bioset(NULL, DIV_ROUND_UP(sectors, PAGE_SECTORS), orig->bi_opf, GFP_NOFS, &fs->bio_read);
		bch2_bio_alloc_pages_pool(fs, read_bio, sectors << 9);
	} else {
		read_bio = orig;
		pick.ptr.offset += pick.crc.offset;
		pick.crc.offset = 0;
		pick.crc.compressed_size = pick.crc.uncompressed_size = pick.crc.live_size = bvec_iter_sectors(read_bio->bi_iter);
	}

	assert(bio_sectors(read_bio) == pick.crc.compressed_size);

	read_bio->bi_iter.bi_sector = pick.ptr.offset;

	struct bch_dev *dev = bch2_dev_get_ioref(fs, pick.ptr.dev, READ, BCH_DEV_READ_REF_io_read);
	bio_set_dev(read_bio, dev->disk_sb.bdev);
	submit_bio_wait(read_bio);

	if (recovery_read_endio(settings, ctx, fs, read_bio, &pick) > 0) {
		verbose(settings, "Read failed. Retrying...\n");
		return recovery_read_extent(settings, ctx, fs);
	}

	return 0;
}

static int recover_inode_data(struct recover_settings *settings, struct bch_fs *fs, struct bkey_i *key)
{
	assert(bkey_extent_is_data(&key->k));
	settings->extents_total++;

	// Size in extent represent 512 byte sectors.
	u64 size = le32_to_cpu(key->k.size) * 512;
	if (bkey_extent_is_inline_data(&key->k)) {
		// Size might be less than a sector in case of inline data.
		size = bkey_inline_data_bytes(&key->k);
	}

	void *data = vzalloc(size);
	if (!data) {
		printf("ERROR: unable to allocate memory for extent data.\n");
		return -1;
	}

	struct bio *bio = bio_alloc_bioset(NULL, 1, REQ_OP_READ|REQ_SYNC, GFP_NOFS, &fs->bio_read);
	if (!bio) {
		printf("ERROR: unable to allocate BIO for read.\n");
		return -1;
	}
	bio_add_page(bio, vmalloc_to_page(data), size, 0);

	struct bch_io_failures failed = { .nr = 0 };
	struct recover_context ctx = {
		.inode = le64_to_cpu(key->k.p.inode),
		.size = size,
		// Offset denotes the /end sector/ so calculate backwards using size.
		.offset = (le64_to_cpu(key->k.p.offset) - le32_to_cpu(key->k.size)) * 512,
		.data = data,
		.bio = bio,
		.key = key,
		.failed = &failed,
		.failed_csum = false,
	};
	if (recovery_read_extent(settings, &ctx, fs) < 0) {
		printf("ERROR: failed to read extent data.\n");
		return -1;
	}

	assert(bio->bi_status == 0);

	int rc = write_to_recovery_file(settings, &ctx);
	bio_put(bio);
	free(data);
	return rc;
}

static int recover_inode_details(struct recover_settings *settings, struct bch_fs *fs, struct bkey_i *key)
{
	assert(bkey_is_inode(&key->k));

	u64 inode = le64_to_cpu(key->k.p.offset);

	verbose(settings, "Unpacking information about inode %llu...\n", inode);

	struct bch_inode_unpacked inode_details;
	if (bch2_inode_unpack(bkey_i_to_s_c(key), &inode_details)) {
		printf("ERROR: failed to unpack inode information from bkey.\n");
		return -1;
	}

	size_t filenameSize = strlen(settings->target_dir) + 25;
	char filename[filenameSize];
	if (snprintf(filename, filenameSize, "%s/%llu", settings->target_dir, inode) < 0) {
		return -1;
	}

	verbose(settings, "Updating file size for %s...\n", filename);

	if (truncate(filename, inode_details.bi_size) < 0) {
		verbose(settings, "Failed to truncate file %s: %d\n", filename, errno);
		return 0;
	}

	verbose(settings, "File truncated!\n");

	settings->files_inodes++;
	return 0;
}

static int do_recover_files(struct recover_settings *settings, struct bch_fs *fs)
{
	struct journal_replay *p, **_p;
	struct genradix_iter iter;

	genradix_for_each(&fs->journal_entries, iter, _p) {
		p = *_p;
		if (!p || !should_recover(settings, &p->j)) {
			continue;
		}

		verbose(settings, "Processing journal entry %llu...\n", le64_to_cpu(p->j.seq));

		bool processing_unlink_transaction = false;
		bool processing_inode_rm_transaction = false;
		for (struct jset_entry *entry = p->j.start; entry != vstruct_last(&p->j); entry = vstruct_next(entry)) {
			if (entry_is_transaction_start(entry)) {
				processing_unlink_transaction = is_unlink_transaction(entry);
				processing_inode_rm_transaction = is_inode_rm_transaction(entry);
				continue;
			}

			if ((!processing_unlink_transaction && !processing_inode_rm_transaction) || entry->type != BCH_JSET_ENTRY_overwrite) {
				continue;
			}

			jset_entry_for_each_key(entry, key) {
				if (processing_unlink_transaction) {
					if (recover_unlink_details(settings, key) < 0) {
						return -1;
					}
				}

				if (processing_inode_rm_transaction) {
					if (bkey_extent_is_data(&key->k)) {
						if (recover_inode_data(settings, fs, key) < 0) {
							struct printbuf buf = PRINTBUF;
							bch2_bkey_val_to_text(&buf, fs, bkey_i_to_s_c(key));
							printf("ERROR: problem while processing extent: %s\n", buf.buf);
							printbuf_exit(&buf);
							return -1;
						}
					} else if (bkey_is_inode(&key->k)) {
						if (recover_inode_details(settings, fs, key) < 0) {
							return -1;
						}
					}
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
		{ "end-time", required_argument, NULL, 'e' },
		{ "ignore-csum", no_argument, NULL, 'i' },
		{ "zero-fill", no_argument, NULL, 'z' },
		{ "use-last", no_argument, NULL, 'l' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL }
	};

	struct bch_opts opts = bch2_opts_empty();
	opt_set(opts, noexcl, true);
	opt_set(opts, nochanges, true);
	opt_set(opts, norecovery, true);
	opt_set(opts, read_only, true);
	opt_set(opts, degraded, BCH_DEGRADED_yes);
	opt_set(opts, retain_recovery_info, true);
	opt_set(opts, read_journal_only, true);
	opt_set(opts, read_entire_journal, true);

	struct recover_settings settings = {
		.target_dir = NULL,
		.start_time = 0,
		.end_time = 0,
		.ignore_csum = false,
		.zero_fill = false,
		.use_last = false,
		.verbose = false,
		.extents_total = 0,
		.extents_written = 0,
		.extents_failed = 0,
		.extents_csum = 0,
		.extents_decompress = 0,
		.files_names = 0,
		.files_inodes = 0,
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "t:s:e:izlvh", longopts, NULL)) != -1)
		switch (opt) {
		case 't':
			settings.target_dir = strdup(optarg);
			break;
		case 's':
			if (kstrtou64(optarg, 10, &settings.start_time))
				die("error parsing start_time");
			break;
		case 'e':
			if (kstrtou64(optarg, 10, &settings.end_time))
				die("error parsing end_time");
			break;
		case 'i':
			settings.ignore_csum = true;
			break;
		case 'z':
			settings.zero_fill = true;
			break;
		case 'l':
			settings.use_last = true;
			break;
		case 'v':
			opt_set(opts, verbose, true);
			settings.verbose = true;
			break;
		case 'h':
			recover_files_usage();
			exit(EXIT_SUCCESS);
		}
	args_shift(optind);

	if (!settings.target_dir) {
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
	int rc = do_recover_files(&settings, c);
	if (rc < 0) {
		printf("Problem encountered during recovery. Aborted.\n");
	}

	printf("Recovery finished. Found %llu extents:\n", settings.extents_total);
	printf("  - %llu extents recovered and written\n", settings.extents_written);
	printf("  - %llu extents with read failures\n", settings.extents_failed);
	if (settings.extents_failed > 0) {
		printf("    - %llu extents with csum failures\n", settings.extents_csum);
		printf("    - %llu extents with decompress failures\n", settings.extents_decompress);
	}
	printf("  - %llu file names recovered\n", settings.files_names);
	printf("  - %llu file metadata recovered\n", settings.files_inodes);

	bch2_fs_stop(c);
	bch2_darray_str_exit(&devs);
	free(settings.target_dir);

	return rc;
}
