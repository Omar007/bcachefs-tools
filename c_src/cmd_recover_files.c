#include <getopt.h>

#include "cmds.h"

#include "libbcachefs/btree_io.h"
#include "libbcachefs/buckets.h"
#include "libbcachefs/dirent.h"
#include "libbcachefs/io_read.h"
#include "libbcachefs/io_write.h"
#include "libbcachefs/journal_io.h"

#define verbose(_settings, ...) do { \
	if (_settings->verbose) { \
		printf(__VA_ARGS__); \
	} \
} while (0)

#define print_bch(_print) do { \
	struct printbuf buf = PRINTBUF; \
	_print; \
	if (buf.size) { \
		printf("%s\n", buf.buf); \
	} \
	printbuf_exit(&buf); \
} while (0)

struct recover_settings {
	char *target_dir;
	u64 start_time;
	u64 end_time;
	bool ignore_csum;
	bool zero_extent;
	bool skip_extent;
	bool use_last_extent;
	bool scan_bset;
	bool scan_jset;
	bool use_journal;
	u64 scan_read_limit;
	darray_u64 included_inodes;
	darray_u64 excluded_inodes;
	bool exclude_live_inodes;
	bool dry_run;
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
	struct bkey_s_c *key;
	struct bch_io_failures *failed;
	bool failed_csum;
	bool failed_decompress;
};

static void recover_files_usage(void)
{
	puts("bcachefs recover-files - Attempt to recover files using on-disk filesystem information\n"
	     "Usage: bcachefs recover-files [OPTION]... <devices>\n"
	     "\n"
	     "Options:\n"
	     "  -t, --target-dir           Target directory to place the recovered files in. USE A LOCATION ON A DIFFERENT FILESYSTEM!\n"
	     "                             Fail to do so and risk destroying the data you're trying to recover!\n"
	     "  -s, --start-time           The time (in Unix time) after which data should be recovered (if detectable).\n"
	     "  -e, --end-time             The time (in Unix time) before which data should be recovered (if detectable).\n"
	     "  -c, --ignore-csum          Ignore checksum failures and accept the data as-is.\n"
	     "  -z, --zero-extent          Zero fill extent data if it can not (reliably) be read.\n"
	     "  -Z, --skip-extent          Skip and don't write any extent data if it can not (reliably) be read.\n"
	     "  -l, --last-read-extent     Write out last read extent data if it can not (reliably) be read.\n"
	     "  -B, --scan-bset            Scan each member disk for extent data. Slow but should recover as much as possible.\n"
	     "  -J, --scan-jset            Scan each member disk for journal data. Should recover a good amount.\n"
	     "  -j, --use-journal          Use the live journal for data recovery. Quick but less complete.\n"
	     "  -m, --scan-read-limit      The amount of data (in GiB) to read from disk at once during scanning.\n"
	     "  -i, --include-inode        Only recover data for the given inode. Can be specified multiple times.\n"
	     "  -I, --exclude-inode        Don't recover data for the given inode. Can be specified multiple times.\n"
	     "  -X, --exclude-live-inodes  Don't recover data for inodes that exist in the live filesystem.\n"
	     "  -d, --dry-run              Only read, don't actually write out anything anywhere.\n"
	     "  -v, --verbose              Enable verbose mode for disk operations.\n"
	     "  -h, --help                 Display this help and exit.\n"
	     "Report bugs to <linux-bcachefs@vger.kernel.org>");
}

static bool should_recover_inode(struct recover_settings *settings, struct bch_fs *fs, u64 inode)
{
	if (settings->exclude_live_inodes) {
		struct bch_inode_unpacked inode_details;
		if (!bch2_trans_do(fs, bch2_inode_find_by_inum_nowarn_trans(trans, (subvol_inum){ 1, inode }, &inode_details))) {
			verbose(settings, "Skipping recovery. Inode %llu still exists.\n", inode);
			return false;
		}
	}

	if (!settings->included_inodes.nr && !settings->excluded_inodes.nr) {
		return true;
	}

	darray_for_each(settings->included_inodes, included) {
		if (*included == inode) {
			return true;
		}
	}

	darray_for_each(settings->excluded_inodes, excluded) {
		if (*excluded == inode) {
			verbose(settings, "Skipping recovery. Inode %llu is explicitly excluded.\n", inode);
			return false;
		}
	}

	if (settings->included_inodes.nr) {
		verbose(settings, "Skipping recovery. Inode %llu has not been explicitly requested.\n", inode);
	}
	return !settings->included_inodes.nr;
}

static bool should_recover_jset(struct recover_settings *settings, struct jset *jset)
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

	// If it can not be determined to be within the desired timeframe or not, always recover it.
	verbose(settings, "Unable to determine if it is within the requested timeframe. Ignoring timeframe restriction...\n");
	return true;
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

static int recover_unlink_details(struct recover_settings *settings, struct bch_fs *fs, struct bkey_s_c *key)
{
	struct bkey_s_c_dirent dirent = bkey_s_c_to_dirent(*key);
	if (dirent.v->d_type != DT_REG) {
		return 0;
	}

	u64 inode = le64_to_cpu(dirent.v->d_inum);
	struct qstr dname = bch2_dirent_get_name(dirent);
	verbose(settings, "Found filename record for inode %llu: %s\n", inode, dname.name);

	if (!should_recover_inode(settings, fs, inode) || settings->dry_run) {
		return 0;
	}

	verbose(settings, "Creating symlink for name to inode recovery file...\n");

	size_t filenameSize = strlen(settings->target_dir) + dname.len + 2;
	char filename[filenameSize];
	if (snprintf(filename, filenameSize, "%s/%s", settings->target_dir, dname.name) < 0) {
		return -1;
	}

	size_t targetNameSize = 25;
	char targetName[targetNameSize];
	if (snprintf(targetName, targetNameSize, "./%llu", inode) < 0) {
		return -1;
	}

	if (symlink(targetName, filename) < 0) {
		if (errno == EEXIST) {
			verbose(settings, "%s already exists. Skipping symlink creation.\n", filename);
			return 0;
		} else {
			printf("ERROR: failed to create symlink %s: %s (%d)\n", filename, strerror(errno), errno);
			return -1;
		}
	}

	verbose(settings, "Symlink created: %s -> %s\n", filename, targetName);

	settings->files_names++;
	return 0;
}

static int write_to_recovery_file(struct recover_settings *settings, struct recover_context *ctx)
{
	if (settings->dry_run) {
		return 0;
	}

	verbose(settings, "Writing out extent data to inode recovery file...\n");

	size_t filenameSize = strlen(settings->target_dir) + 25;
	char filename[filenameSize];
	if (snprintf(filename, filenameSize, "%s/%llu", settings->target_dir, ctx->inode) < 0) {
		return -1;
	}

	int fd = open(filename, O_RDWR|O_CREAT, 0600);
	if (fd < 0) {
		printf("ERROR: failed to open target file %s: %s (%d)\n", filename, strerror(errno), errno);
		return -1;
	}

	if (lseek(fd, ctx->offset, SEEK_SET) < 0) {
		printf("ERROR: failed to seek to offset %llu in %s: %s (%d).\n", ctx->offset, filename, strerror(errno), errno);
		close(fd);
		return -1;
	}

	ssize_t written = write(fd, ctx->data, ctx->size);
	if (written != ctx->size) {
		printf("ERROR: failed to write extent data to %s. Wrote: %lu, expected: %llu, err: %s (%d)\n",
			filename, written, ctx->size, strerror(errno), errno);
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
	if (read_bio->bi_status) {
		verbose(settings, "I/O error while reading extent ptr: %s (%d)\n", blk_status_to_str(read_bio->bi_status), read_bio->bi_status);
		return -1;
	}

	if (ctx->bio != read_bio) {
		read_bio->bi_iter.bi_size = pick->crc.compressed_size << SECTOR_SHIFT;
		read_bio->bi_iter.bi_idx = 0;
		read_bio->bi_iter.bi_bvec_done = 0;
	}

	verbose(settings, "Verifying checksum...\n");
	struct nonce nonce = extent_nonce(ctx->key->k->bversion, pick->crc);
	struct bch_csum csum = bch2_checksum_bio(fs, pick->crc.csum_type, nonce, read_bio);
	ctx->failed_csum = bch2_crc_cmp(pick->crc.csum, csum);
	if (ctx->failed_csum) {
		print_bch(bch2_csum_err_msg(&buf, pick->crc.csum_type, pick->crc.csum, csum));
		return -1;
	}

	if (crc_is_compressed(pick->crc)) {
		assert(ctx->bio != read_bio);

		if (bch2_encrypt_bio(fs, pick->crc.csum_type, nonce, read_bio)) {
			return -1;
		}

		verbose(settings, "Decompressing extent...\n");
		ctx->failed_decompress = bch2_bio_uncompress(fs, read_bio, ctx->bio, ctx->bio->bi_iter, pick->crc);
		if (ctx->failed_decompress) {
			printf("Failed to decompress extent.\n");
			return -1;
		}
	} else {
		/* don't need to decrypt the entire bio: */
		nonce = nonce_add(nonce, pick->crc.offset << SECTOR_SHIFT);
		bio_advance(read_bio, pick->crc.offset << SECTOR_SHIFT);

		if (bch2_encrypt_bio(fs, pick->crc.csum_type, nonce, read_bio)) {
			return -1;
		}
	}
	return 0;
}

static int recovery_read_extent(struct recover_settings *settings, struct recover_context *ctx, struct bch_fs *fs)
{
	struct bio *orig = ctx->bio;

	if (bkey_extent_is_inline_data(ctx->key->k)) {
		unsigned bytes = min_t(unsigned, orig->bi_iter.bi_size, bkey_inline_data_bytes(ctx->key->k));
		swap(orig->bi_iter.bi_size, bytes);
		memcpy_to_bio(orig, orig->bi_iter, bkey_inline_data_p(*ctx->key));
		swap(orig->bi_iter.bi_size, bytes);
		bio_advance_iter(orig, &orig->bi_iter, bytes);
		zero_fill_bio_iter(orig, orig->bi_iter);
		return 0;
	}

	struct extent_ptr_decoded pick;
	if (bch2_bkey_pick_read_device(fs, *ctx->key, ctx->failed, &pick, -1) < 0) {
		settings->extents_failed++;

		if (ctx->failed_csum) {
			settings->extents_csum++;

			if (!settings->ignore_csum) {
				printf("ERROR: no device to read from with a valid checksum.\n");
				return -1;
			}
		}

		if (ctx->failed_decompress) {
			settings->extents_decompress++;
		}

		if (settings->zero_extent) {
			verbose(settings, "Read failed. Zero-filling...\n");
			zero_fill_bio_iter(orig, orig->bi_iter);
			return 0;
		}

		if (settings->skip_extent) {
			verbose(settings, "Read failed. Skipping...\n");
			return -2;
		}

		if (settings->use_last_extent && ctx->failed->nr) {
			verbose(settings, "Read failed. Using last read extent data...\n");
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
		bch2_bio_alloc_pages_pool(fs, read_bio, sectors << SECTOR_SHIFT);
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

	int rc = 0;
	if (recovery_read_endio(settings, ctx, fs, read_bio, &pick) < 0) {
		bch2_mark_io_failure(ctx->failed, &pick, ctx->failed_csum);
		rc = ctx->failed->nr;

		printf("WARN: Read attempt %d failed: ", ctx->failed->nr);
		print_bch(bch2_extent_ptr_to_text(&buf, fs, &pick.ptr));
	}
	if (orig != read_bio) {
		bch2_bio_free_pages_pool(fs, read_bio);
		bio_put(read_bio);
	}
	return rc;
}

static int recover_inode_data(struct recover_settings *settings, struct bch_fs *fs, struct bkey_s_c *key)
{
	// Size in extent represent 512 byte sectors.
	u64 size = key->k->size << SECTOR_SHIFT;
	if (bkey_extent_is_inline_data(key->k)) {
		// Size might be less than a sector in case of inline data.
		size = bkey_inline_data_bytes(key->k);
	}

	u64 inode = key->k->p.inode;
	u64 offset = bkey_start_offset(key->k) << SECTOR_SHIFT;

	verbose(settings, "Found extent record for inode %llu: %llu bytes @ %llu\n", inode, size, offset);

	if (!should_recover_inode(settings, fs, inode)) {
		return 0;
	}

	settings->extents_total++;

	if (!size) {
		// Shortcut for 0-byte extents; no need to read/write anything. Just create target file.
		return write_to_recovery_file(settings, &(struct recover_context){ .inode = inode });
	}

	struct recover_context ctx = {
		.inode = inode,
		.size = size,
		.offset = offset,
		.data = vmalloc(size),
		.bio = bio_alloc_bioset(NULL, 1, REQ_OP_READ|REQ_SYNC, GFP_NOFS, &fs->bio_read),
		.key = key,
		.failed = &(struct bch_io_failures){ .nr = 0 },
		.failed_csum = false,
	};

	if (!ctx.data || !ctx.bio) {
		printf("ERROR: unable to allocate memory for read.\n");
		return -1;
	}

	int rc = 0;
	do {
		memset(ctx.data, 0, size);
		bio_reset(ctx.bio, NULL, REQ_OP_READ|REQ_SYNC);
		bio_add_page(ctx.bio, vmalloc_to_page(ctx.data), size, 0);
	} while ((rc = recovery_read_extent(settings, &ctx, fs)) > 0);

	switch (rc) {
		case 0:
			assert(ctx.bio->bi_status == 0);
			rc = write_to_recovery_file(settings, &ctx);
			break;
		case -2:
			// Shortcut for skipped extents; no need to read/write anything. Just create target file.
			rc = write_to_recovery_file(settings, &(struct recover_context){ .inode = inode });
			break;
		default:
			printf("ERROR: failed to read extent data.\n");
			break;
	}

	free(ctx.data);
	bio_put(ctx.bio);
	return rc;
}

static int recover_inode_details(struct recover_settings *settings, struct bch_fs *fs, struct bkey_s_c *key)
{
	u64 inode = key->k->p.offset;

	verbose(settings, "Found metadata for inode %llu.\n", inode);

	if (!should_recover_inode(settings, fs, inode) || settings->dry_run) {
		return 0;
	}

	verbose(settings, "Unpacking inode details...\n");

	struct bch_inode_unpacked inode_details;
	if (bch2_inode_unpack(*key, &inode_details)) {
		printf("WARN: failed to unpack inode information from bkey for %llu. Skipping...\n", inode);
		return 0;
	}

	if (!inode_details.bi_size) {
		// Do not truncate recovered files to 0...
		return 0;
	}

	size_t filenameSize = strlen(settings->target_dir) + 25;
	char filename[filenameSize];
	if (snprintf(filename, filenameSize, "%s/%llu", settings->target_dir, inode) < 0) {
		return -1;
	}

	verbose(settings, "Updating file size for %s to %llu bytes...\n", filename, inode_details.bi_size);

	if (truncate(filename, inode_details.bi_size) < 0) {
		switch (errno) {
			case ENOENT:
				verbose(settings, "%s does not exist. Skipping truncation...\n", filename);
				return 0;
			case EINVAL:
				verbose(settings, "%s not a file or smaller than target. Skipping truncation...\n", filename);
				return 0;
			default:
				verbose(settings, "Failed to truncate file %s: %s (%d)\n", filename, strerror(errno), errno);
				return -1;
		}
	}

	verbose(settings, "File truncated!\n");

	settings->files_inodes++;
	return 0;
}

static int process_bkey(struct recover_settings *settings, struct bch_fs *fs, struct bkey_s_c *s_c)
{
	struct bkey_validate_context from = {
		.from = BKEY_VALIDATE_btree_node,
		.flags = BCH_VALIDATE_silent,
	};

	switch (s_c->k->type) {
		case KEY_TYPE_dirent:
			from.btree = BTREE_ID_dirents;
			break;
		case KEY_TYPE_inode:
		case KEY_TYPE_inode_v2:
		case KEY_TYPE_inode_v3:
			from.btree = BTREE_ID_inodes;
			break;
		case KEY_TYPE_extent:
		case KEY_TYPE_inline_data:
			from.btree = BTREE_ID_extents;
			break;
		case KEY_TYPE_reflink_v:
		case KEY_TYPE_indirect_inline_data:
			from.btree = BTREE_ID_reflink;
			break;
		default:
			verbose(settings, "Ignoring bkey with type %s. Nothing implemented.\n", s_c->k->type < KEY_TYPE_MAX ? bch2_bkey_types[s_c->k->type] : "invalid");
			return 0;
	}

	if (bch2_bkey_validate(fs, *s_c, from)) {
		verbose(settings, "Validation for found bkey failed. Skipping...\n");
		return 0;
	}

	int rc = 0;
	switch (s_c->k->type) {
		case KEY_TYPE_dirent:
			rc = recover_unlink_details(settings, fs, s_c);
			break;
		case KEY_TYPE_inode:
		case KEY_TYPE_inode_v2:
		case KEY_TYPE_inode_v3:
			rc = recover_inode_details(settings, fs, s_c);
			break;
		case KEY_TYPE_extent:
		case KEY_TYPE_inline_data:
		case KEY_TYPE_reflink_v:
		case KEY_TYPE_indirect_inline_data:
			rc = recover_inode_data(settings, fs, s_c);
			break;
		default:
			break;
	}

	if (rc < 0) {
		printf("ERROR: problem while processing %s: ", bch2_bkey_types[s_c->k->type]);
		print_bch(bch2_bkey_val_to_text(&buf, fs, *s_c));
	}

	return rc;
}

static int process_jset(struct recover_settings *settings, struct bch_fs *fs, struct jset *jset)
{
	bool processing_unlink_transaction = false;
	bool processing_inode_rm_transaction = false;

	verbose(settings, "Processing journal entry %llu...\n", le64_to_cpu(jset->seq));

	vstruct_for_each_safe(jset, entry) {
		if (entry_is_transaction_start(entry)) {
			processing_unlink_transaction = is_unlink_transaction(entry);
			processing_inode_rm_transaction = is_inode_rm_transaction(entry);
			continue;
		}

		if ((!processing_unlink_transaction && !processing_inode_rm_transaction) || entry->type != BCH_JSET_ENTRY_overwrite) {
			continue;
		}

		jset_entry_for_each_key(entry, key) {
			struct bkey_s_c s_c = bkey_i_to_s_c(key);
			if (process_bkey(settings, fs, &s_c) < 0) {
				return -1;
			}
		}
	}
	return 0;
}

static int do_journal_recovery(struct recover_settings *settings, struct bch_fs *fs)
{
	struct journal_replay *p, **_p;
	struct genradix_iter iter;

	genradix_for_each(&fs->journal_entries, iter, _p) {
		p = *_p;
		if (!p || !should_recover_jset(settings, &p->j)) {
			continue;
		}

		if (process_jset(settings, fs, &p->j) < 0) {
			return -1;
		}
	}
	return 0;
}

// Copied over from journal_io.c
static struct nonce journal_nonce(const struct jset *jset)
{
	return (struct nonce) {{
		[0] = 0,
		[1] = ((__le32 *) &jset->seq)[0],
		[2] = ((__le32 *) &jset->seq)[1],
		[3] = BCH_NONCE_JOURNAL,
	}};
}

static int scan_bset(struct recover_settings *settings, struct bch_dev *dev, struct btree_node *bn, u64 offset_bytes)
{
	if (le64_to_cpu(bn->magic) != bset_magic(dev->fs)) {
		return 0;
	}

	struct bset *bset = NULL;
	struct bch_csum *csum = NULL;
	struct bch_csum csum_calc;

	u64 sectors = 0;
	if (!offset_bytes) {
		verbose(settings, "Found btree_node!\n");
		sectors = vstruct_sectors(bn, dev->fs->block_bits);

		bset = &bn->keys;
		csum = &bn->csum;
		csum_calc = csum_vstruct(dev->fs, BSET_CSUM_TYPE(bset), btree_nonce(bset, 0), bn);
	} else {
		struct btree_node_entry *bne = (void *) bn + offset_bytes;
		sectors = vstruct_sectors(bne, dev->fs->block_bits);
		if (offset_bytes + (sectors << SECTOR_SHIFT) > bucket_bytes(dev)) {
			verbose(settings, "No more btree_node_entry items in bucket.\n");
			return sectors;
		}

		verbose(settings, "Found btree_node_entry!\n");

		bset = &bne->keys;
		csum = &bne->csum;
		csum_calc = csum_vstruct(dev->fs, BSET_CSUM_TYPE(bset), btree_nonce(bset, offset_bytes), bne);
	}

	assert(bset && csum);

	if (bch2_crc_cmp(*csum, csum_calc)) {
		print_bch(bch2_csum_err_msg(&buf, BSET_CSUM_TYPE(bset), *csum, csum_calc));
		printf("Skipping bset...\n");
		return sectors;
	}

	if (bset_encrypt(dev->fs, bset, offset_bytes)) {
		printf("ERROR: Failed to decrypt bset.\n");
		return -1;
	}

	if (!offset_bytes) {
		int rc = 0;
		print_bch(rc = bch2_bkey_format_invalid(NULL, &bn->format, 0, &buf));
		if (rc) {
			printf("Invalid format in btree_node. Skipping bucket...\n");
			return dev->mi.bucket_size;
		}
	}

	vstruct_for_each_safe(bset, pkey) {
		struct bkey key = bkey_packed(pkey) ? __bch2_bkey_unpack_key(&bn->format, pkey) : *packed_to_bkey_c(pkey);
		struct bkey_s_c s_c = {
			.k = &key,
			.v = bkeyp_val(&bn->format, pkey),
		};
		if (process_bkey(settings, dev->fs, &s_c) < 0) {
			return -1;
		}
	}

	return sectors;
}

static int scan_jset(struct recover_settings *settings, struct bch_fs *fs, struct jset *jset)
{
	if (le64_to_cpu(jset->magic) != jset_magic(fs)) {
		return 0;
	}

	verbose(settings, "Found jset!\n");

	if (le64_to_cpu(jset->seq) < fs->journal.oldest_seq_found_ondisk) {
		printf("Found jset record is no longer present in live journal!\n");
	}

	enum bch_csum_type csum_type = JSET_CSUM_TYPE(jset);
	struct nonce nonce = journal_nonce(jset);
	struct bch_csum csum_calc = csum_vstruct(fs, csum_type, nonce, jset);
	if (bch2_crc_cmp(jset->csum, csum_calc)) {
		print_bch(bch2_csum_err_msg(&buf, csum_type, jset->csum, csum_calc));
		printf("Skipping jset...\n");
		return vstruct_sectors(jset, fs->block_bits);
	}

	if (bch2_encrypt(fs, csum_type, nonce, jset->encrypted_start, vstruct_end(jset) - (void *) jset->encrypted_start)) {
		printf("ERROR: Failed to decrypt jset.\n");
		return -1;
	}

	if (should_recover_jset(settings, jset) && process_jset(settings, fs, jset) < 0) {
		printf("ERROR: Failed to process jset.\n");
		return -1;
	}

	return vstruct_sectors(jset, fs->block_bits);
}

static int scan_bucket(struct recover_settings *settings, struct bch_dev *dev, void *data)
{
	for (u16 offset = 0, sectors = 0; offset < dev->mi.bucket_size; offset += max(sectors, 1), sectors = 0) {
		if (!sectors && settings->scan_bset) {
			sectors = scan_bset(settings, dev, data, offset << SECTOR_SHIFT);
		}

		if (!sectors && settings->scan_jset) {
			sectors = scan_jset(settings, dev->fs, data + (offset << SECTOR_SHIFT));
		}

		if (sectors < 0) {
			return -1;
		}
	}

	return 0;
}

static int scan_members(struct recover_settings *settings, struct bch_fs *fs)
{
	struct bio *bio = bio_alloc_bioset(NULL, 1, REQ_OP_READ|REQ_SYNC, GFP_NOFS, &fs->bio_read);
	if (!bio) {
		printf("ERROR: unable to allocate BIO for read.\n");
		return -1;
	}

	for_each_online_member(fs, dev, 0) {
		u64 bsize_in_bytes = bucket_bytes(dev);
		u64 chunk_size_in_buckets = min(max(bsize_in_bytes, settings->scan_read_limit) / bsize_in_bytes, dev->mi.nbuckets);
		u64 chunk_size_in_bytes = bsize_in_bytes * chunk_size_in_buckets;

		verbose(settings, "Processing member %d: buckets=%llu, bsectors=%d, bsize=%llu, bsperread=%llu\n",
			dev->dev_idx, dev->mi.nbuckets, dev->mi.bucket_size, bsize_in_bytes, chunk_size_in_buckets);

		void *data = vmalloc(chunk_size_in_bytes);
		if (!data) {
			printf("ERROR: unable to allocate memory for bucket data.\n");
			free(bio);
			return -1;
		}

		for (u64 bucket = 0; bucket < dev->mi.nbuckets;) {
			u64 buckets_to_read = min(chunk_size_in_buckets, dev->mi.nbuckets - bucket);
			u64 read_size = bsize_in_bytes * buckets_to_read;

			verbose(settings, "Reading bucket %llu through %llu (%llu bytes)...\n", bucket, bucket + buckets_to_read, read_size);

			memset(data, 0, chunk_size_in_bytes);
			bio_reset(bio, NULL, REQ_OP_READ|REQ_SYNC);
			bio_add_page(bio, vmalloc_to_page(data), read_size, 0);
			bio_set_dev(bio, dev->disk_sb.bdev);
			bio->bi_iter.bi_sector = bucket_to_sector(dev, bucket);
			submit_bio_wait(bio);

			if (bio->bi_status) {
				printf("ERROR: unexpected I/O error while reading member disk %d: %s (%d)\n", dev->dev_idx, blk_status_to_str(bio->bi_status), bio->bi_status);
				free(data);
				bio_put(bio);
				return -1;
			}

			void *data_iter = data;
			for (u64 i = 0; i < buckets_to_read; i++) {
				if (scan_bucket(settings, dev, data_iter) < 0) {
					free(data);
					bio_put(bio);
					return -1;
				}
				data_iter += bsize_in_bytes;
			}

			bucket += buckets_to_read;
		}

		free(data);
	}

	bio_put(bio);
	return 0;
}

static int do_recover_files(struct recover_settings *settings, struct bch_fs *fs)
{
	if (settings->scan_bset || settings->scan_jset) {
		printf("Scanning member disks...\n");
		if (scan_members(settings, fs) < 0) {
			return -1;
		}
	}

	if (settings->use_journal) {
		printf("Reading journal...\n");
		if (do_journal_recovery(settings, fs) < 0) {
			return -1;
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
		{ "ignore-csum", no_argument, NULL, 'c' },
		{ "zero-extent", no_argument, NULL, 'z' },
		{ "skip-extent", no_argument, NULL, 'Z' },
		{ "last-read-extent", no_argument, NULL, 'l' },
		{ "scan-bset", no_argument, NULL, 'B' },
		{ "scan-jset", no_argument, NULL, 'J' },
		{ "use-journal", no_argument, NULL, 'j' },
		{ "scan-read-limit", required_argument, NULL, 'm' },
		{ "include-inode", required_argument, NULL, 'i' },
		{ "exclude-inode", required_argument, NULL, 'I' },
		{ "exclude-live-inodes", no_argument, NULL, 'X' },
		{ "dry-run", no_argument, NULL, 'd' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL }
	};

	struct recover_settings settings = {
		.target_dir = NULL,
		.start_time = 0,
		.end_time = 0,
		.ignore_csum = false,
		.zero_extent = false,
		.skip_extent = false,
		.use_last_extent = false,
		.scan_bset = false,
		.scan_jset = false,
		.use_journal = false,
		// Default limit of 1 GiB
		.scan_read_limit = (1 << 30),
		.included_inodes = {},
		.excluded_inodes = {},
		.exclude_live_inodes = false,
		.dry_run = false,
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
	while ((opt = getopt_long(argc, argv, "t:s:e:czZlBJjm:i:I:Xdvh", longopts, NULL)) != -1)
		switch (opt) {
		case 't':
			settings.target_dir = strdup(optarg);
			break;
		case 's':
			if (kstrtou64(optarg, 10, &settings.start_time))
				die("error parsing start-time value");
			break;
		case 'e':
			if (kstrtou64(optarg, 10, &settings.end_time))
				die("error parsing end-time value");
			break;
		case 'c':
			settings.ignore_csum = true;
			break;
		case 'z':
			settings.zero_extent = true;
			break;
		case 'Z':
			settings.skip_extent = true;
			break;
		case 'l':
			settings.use_last_extent = true;
			break;
		case 'B':
			settings.scan_bset = true;
			break;
		case 'J':
			settings.scan_jset = true;
			break;
		case 'j':
			settings.use_journal = true;
			break;
		case 'm':
			u64 gib_limit = 0;
			if (kstrtou64(optarg, 10, &gib_limit))
				die("error parsing scan-read-limit value");
			settings.scan_read_limit = gib_limit << 30;
			break;
		case 'i':
			u64 include_inode = 0;
			if (kstrtou64(optarg, 10, &include_inode))
				die("error parsing include-inode value");
			darray_push(&settings.included_inodes, include_inode);
			break;
		case 'I':
			u64 exclude_inode = 0;
			if (kstrtou64(optarg, 10, &exclude_inode))
				die("error parsing exclude-inode value");
			darray_push(&settings.excluded_inodes, exclude_inode);
			break;
		case 'X':
			settings.exclude_live_inodes = true;
			break;
		case 'd':
			settings.dry_run = true;
			break;
		case 'v':
			settings.verbose = true;
			break;
		case 'h':
			recover_files_usage();
			exit(EXIT_SUCCESS);
		}
	args_shift(optind);

	if (!settings.target_dir && !settings.dry_run) {
		die("Please supply a target directory");
	}

	unsigned recovery_method_count = settings.scan_bset + settings.scan_jset + settings.use_journal;
	if (!recovery_method_count) {
		die("Please select recovery method(s)");
	} else if (settings.use_journal && settings.exclude_live_inodes) {
		die("-X flag not supported when recovering from live journal");
	} else if (recovery_method_count > 1) {
		printf("WARN: Multiple recovery methods selected!\n"
		       "WARN: Be aware that data recovered using one method may be overwritten by another.\n");
	}

	if (!argc) {
		die("Please supply device(s) to open");
	}

	struct bch_opts opts = bch2_opts_empty();
	opt_set(opts, noexcl, true);
	opt_set(opts, nochanges, true);
	opt_set(opts, norecovery, true);
	opt_set(opts, read_only, true);
	opt_set(opts, degraded, BCH_DEGRADED_yes);
	opt_set(opts, read_journal_only, true);
	opt_set(opts, read_entire_journal, settings.use_journal);
	opt_set(opts, retain_recovery_info, settings.use_journal);
	opt_set(opts, verbose, settings.verbose);

	darray_str devs = get_or_split_cmdline_devs(argc, argv);
	struct bch_fs *c = bch2_fs_open(devs.data, devs.nr, opts);
	if (IS_ERR(c)) {
		die("error opening %s: %s", argv[0], bch2_err_str(PTR_ERR(c)));
	}

	printf("Starting recovery...\n");
	int rc = do_recover_files(&settings, c);
	if (rc < 0) {
		printf("ERROR: Problem encountered during recovery. Aborted.\n");
	}

	printf("Recovery finished. Found %llu extents using %u recovery method(s):\n", settings.extents_total, recovery_method_count);
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
