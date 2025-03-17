#include <getopt.h>

#include "cmds.h"

#include "libbcachefs/btree_io.h"
#include "libbcachefs/buckets.h"
#include "libbcachefs/dirent.h"
#include "libbcachefs/io_read.h"
#include "libbcachefs/io_write.h"
#include "libbcachefs/journal_io.h"

struct recover_settings {
	char *target_dir;
	u64 start_time;
	u64 end_time;
	bool ignore_csum;
	bool zero_fill;
	bool use_last;
	bool scan_bset;
	bool scan_jset;
	bool use_journal;
	u64 scan_read_limit;
	darray_u64 included_inodes;
	darray_u64 excluded_inodes;
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
	puts("bcachefs recover-files - Attempt to recover deleted files using journal information\n"
	     "Usage: bcachefs recover-files [OPTION]... <devices>\n"
	     "\n"
	     "Options:\n"
	     "  -t, --target-dir      Target directory to place the recovered files in. USE A LOCATION ON A DIFFERENT FILESYSTEM!\n"
	     "                        Fail to do so and risk destroying the data you're trying to recover!\n"
	     "  -s, --start-time      The time (in Unix time) after which deleted data should be recovered (if detectable).\n"
	     "  -e, --end-time        The time (in Unix time) before which deleted data should be recovered (if detectable).\n"
	     "  -c, --ignore-csum     Ignore checksum failures and accept the data as-is.\n"
	     "  -z, --zero-fill       Zero fill extent data if it can not (reliably) be read instead of bailing out.\n"
	     "  -l, --use-last        Write out last read extent data if it can not (reliably) be read instead of bailing out.\n"
	     "  -B, --scan-bset       Scan each member disk for extent data. Slow but should recover as much as possible.\n"
	     "  -J, --scan-jset       Scan each member disk for journal data. Should recover a good amount.\n"
	     "  -j, --use-journal     Use the live journal for data recovery. Quick but less complete.\n"
	     "  -m, --scan-read-limit The amount of data (in GiB) to read from disk at once during scanning.\n"
	     "  -i, --include-inode   Only recover data for the given inode. Can be specified multiple times.\n"
	     "  -I, --exclude-inode   Don't recover data for the given inode. Can be specified multiple times.\n"
	     "  -d, --dry-run         Only read, don't actually write out anything anywhere.\n"
	     "  -v, --verbose         Enable verbose mode for disk operations.\n"
	     "  -h, --help            Display this help and exit.\n"
	     "Report bugs to <linux-bcachefs@vger.kernel.org>");
}

static inline int verbose(struct recover_settings *settings, const char *fmt, ...)
{
	int rc = 0;
	if (settings->verbose) {
		va_list args;
		va_start(args, fmt);
		rc = vprintf(fmt, args);
		va_end(args);
	}
	return rc;
}

static bool should_recover_inode(struct recover_settings *settings, u64 inode)
{
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

static int recover_unlink_details(struct recover_settings *settings, struct bkey_s_c *key)
{
	assert(key->k->type == KEY_TYPE_dirent);

	struct bkey_s_c_dirent dirent = bkey_s_c_to_dirent(*key);
	if (dirent.v->d_type != DT_REG) {
		return 0;
	}

	u64 inode = le64_to_cpu(dirent.v->d_inum);
	if (!should_recover_inode(settings, inode)) {
		return 0;
	}

	struct qstr dname = bch2_dirent_get_name(dirent);
	verbose(settings, "Found deleted filename record for inode %llu: %s\n", inode, dname.name);

	if (settings->dry_run) {
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
	struct bio *orig = ctx->bio;
	struct bch_io_failures *failed = ctx->failed;
	struct nonce nonce = extent_nonce(ctx->key->k->bversion, pick->crc);

	if (orig != read_bio) {
		read_bio->bi_iter.bi_size = pick->crc.compressed_size << 9;
		read_bio->bi_iter.bi_idx = 0;
		read_bio->bi_iter.bi_bvec_done = 0;
	}

	verbose(settings, "Verifying checksum...\n");
	struct bch_csum csum = bch2_checksum_bio(fs, pick->crc.csum_type, nonce, read_bio);
	ctx->failed_csum = bch2_crc_cmp(pick->crc.csum, csum);
	if (ctx->failed_csum) {
		struct printbuf buf = PRINTBUF;
		bch2_csum_err_msg(&buf, pick->crc.csum_type, pick->crc.csum, csum);
		printf("%s\n", buf.buf);
		printbuf_exit(&buf);

		goto retry;
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
	if (bch2_bkey_pick_read_device(fs, *ctx->key, failed, &pick, -1) < 0) {
		settings->extents_failed++;
		if (ctx->failed_csum) {
			settings->extents_csum++;
		}
		if (ctx->failed_decompress) {
			settings->extents_decompress++;
		}

		if (!failed->nr && !settings->zero_fill) {
			printf("ERROR: no device to read from.\n");
			return -1;
		}

		if (ctx->failed_csum && !settings->ignore_csum) {
			printf("ERROR: no device to read from with a valid checksum.\n");
			return -1;
		}

		if (settings->zero_fill) {
			verbose(settings, "Zero-filling...\n");
			zero_fill_bio_iter(orig, orig->bi_iter);
			return 0;
		} else if (settings->use_last) {
			verbose(settings, "Using last read extent data...\n");
			return 0;
		}

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

static int recover_inode_data(struct recover_settings *settings, struct bch_fs *fs, struct bkey_s_c *key)
{
	assert(bkey_extent_is_data(key->k));

	// Size in extent represent 512 byte sectors.
	u64 size = le32_to_cpu(key->k->size) << 9;
	if (bkey_extent_is_inline_data(key->k)) {
		// Size might be less than a sector in case of inline data.
		size = bkey_inline_data_bytes(key->k);
	}

	u64 inode = le64_to_cpu(key->k->p.inode);
	// Offset denotes the /end sector/ so calculate backwards using size.
	u64 offset = (le64_to_cpu(key->k->p.offset) << 9) - size;

	verbose(settings, "Found deleted extent record for inode %llu: %llu bytes @ %llu\n", inode, size, offset);

	if (!should_recover_inode(settings, inode)) {
		return 0;
	}

	settings->extents_total++;

	if (!size) {
		// Don't attempt to recover 0 byte extents.
		verbose(settings, "Skipping empty (0-byte) extent.\n");
		return 0;
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
		.inode = inode,
		.size = size,
		.offset = offset,
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

static int recover_inode_details(struct recover_settings *settings, struct bch_fs *fs, struct bkey_s_c *key)
{
	assert(bkey_is_inode(key->k));

	u64 inode = le64_to_cpu(key->k->p.offset);

	verbose(settings, "Found metadata for inode %llu.\n", inode);

	if (!should_recover_inode(settings, inode) || settings->dry_run) {
		return 0;
	}

	verbose(settings, "Unpacking inode details...\n");

	struct bch_inode_unpacked inode_details;
	if (bch2_inode_unpack(*key, &inode_details)) {
		printf("ERROR: failed to unpack inode information from bkey.\n");
		return -1;
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
		if (errno != ENOENT) {
			verbose(settings, "Failed to truncate file %s: %s (%d)\n", filename, strerror(errno), errno);
		}
		return 0;
	}

	verbose(settings, "File truncated!\n");

	settings->files_inodes++;
	return 0;
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

			if (processing_unlink_transaction) {
				if (recover_unlink_details(settings, &s_c) < 0) {
					return -1;
				}
			}

			if (processing_inode_rm_transaction) {
				if (bkey_extent_is_data(s_c.k)) {
					if (recover_inode_data(settings, fs, &s_c) < 0) {
						struct printbuf buf = PRINTBUF;
						bch2_bkey_val_to_text(&buf, fs, s_c);
						printf("ERROR: problem while processing extent: %s\n", buf.buf);
						printbuf_exit(&buf);
						return -1;
					}
				} else if (bkey_is_inode(s_c.k)) {
					if (recover_inode_details(settings, fs, &s_c) < 0) {
						return -1;
					}
				}
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

static int process_bucket(struct recover_settings *settings, struct bch_dev *dev, void *data)
{
	u64 fs_magic_bset = bset_magic(dev->fs);
	u64 fs_magic_jset = jset_magic(dev->fs);

	for (u64 offset = 0; offset < dev->mi.bucket_size;) {
		if (settings->scan_bset) {
			struct btree_node *bn = data;
			if (le64_to_cpu(bn->magic) == fs_magic_bset) {
				struct bset *bset = NULL;
				struct bch_csum *csum = NULL;
				struct bch_csum csum_calc;
				u64 sectors = 0;

				if (!offset) {
					verbose(settings, "Found btree_node!\n");

					bset = &bn->keys;
					csum = &bn->csum;
					csum_calc = csum_vstruct(dev->fs, BSET_CSUM_TYPE(bset), btree_nonce(bset, 0), bn);
					sectors = vstruct_sectors(bn, dev->fs->block_bits);
				} else {
					verbose(settings, "Found btree_node_entry!\n");

					struct btree_node_entry *bne = data + (offset << 9);

					bset = &bne->keys;
					csum = &bne->csum;
					csum_calc = csum_vstruct(dev->fs, BSET_CSUM_TYPE(bset), btree_nonce(bset, offset << 9), bne);
					sectors = vstruct_sectors(bne, dev->fs->block_bits);
				}

				assert(bset && csum);

				if (bch2_crc_cmp(*csum, csum_calc)) {
					struct printbuf buf = PRINTBUF;
					bch2_csum_err_msg(&buf, BSET_CSUM_TYPE(bset), *csum, csum_calc);
					printf("%s\n", buf.buf);
					printbuf_exit(&buf);

					offset += sectors;
					continue;
				}

				if (bset_encrypt(dev->fs, bset, offset << 9)) {
					printf("Failed to decrypt bset.\n");
					return -1;
				}

				vstruct_for_each_safe(bset, pkey) {
					struct bkey key = bkey_packed(pkey) ? __bch2_bkey_unpack_key(&bn->format, pkey) : *packed_to_bkey_c(pkey);
					struct bkey_s_c s_c = {
						.k = &key,
						.v = bkeyp_val(&bn->format, pkey),
					};

					if (bkey_extent_is_data(s_c.k)) {
						if (recover_inode_data(settings, dev->fs, &s_c) < 0) {
							struct printbuf buf = PRINTBUF;
							bch2_bkey_val_to_text(&buf, dev->fs, s_c);
							printf("ERROR: problem while processing extent: %s\n", buf.buf);
							printbuf_exit(&buf);
							return -1;
						}
					} else if (bkey_is_inode(s_c.k)) {
						if (recover_inode_details(settings, dev->fs, &s_c) < 0) {
							return -1;
						}
					} else if (s_c.k->type == KEY_TYPE_dirent) {
						if (recover_unlink_details(settings, &s_c)) {
							return -1;
						}
					}
				}

				offset += sectors;
				continue;
			}
		}

		if (settings->scan_jset) {
			struct jset *jset = data + (offset << 9);
			if (le64_to_cpu(jset->magic) == fs_magic_jset) {
				verbose(settings, "Found jset!\n");

				if (le64_to_cpu(jset->seq) < dev->fs->journal.oldest_seq_found_ondisk) {
					printf("Found jset record is no longer present in live journal!\n");
				}

				enum bch_csum_type csum_type = JSET_CSUM_TYPE(jset);
				struct nonce nonce = journal_nonce(jset);
				struct bch_csum csum_calc = csum_vstruct(dev->fs, csum_type, nonce, jset);
				u64 sectors = vstruct_sectors(jset, dev->fs->block_bits);
				if (bch2_crc_cmp(jset->csum, csum_calc)) {
					struct printbuf buf = PRINTBUF;
					bch2_csum_err_msg(&buf, csum_type, jset->csum, csum_calc);
					printf("%s\n", buf.buf);
					printbuf_exit(&buf);

					offset += sectors;
					continue;
				}

				if (bch2_encrypt(dev->fs, csum_type, nonce, jset->encrypted_start, vstruct_end(jset) - (void *) jset->encrypted_start)) {
					printf("Failed to decrypt jset.\n");
					return -1;
				}

				if (should_recover_jset(settings, jset) && process_jset(settings, dev->fs, jset) < 0) {
					printf("ERROR: Failed to process jset.\n");
					return -1;
				}

				offset += sectors;
				continue;
			}
		}

		offset++;
	}

	return 0;
}

static int scan_members(struct recover_settings *settings, struct bch_fs *fs)
{
	for_each_online_member(fs, dev, 0) {
		// The bucket_size field records size in 512 byte sectors.
		u64 bsize_in_bytes = dev->mi.bucket_size << 9;

		verbose(settings, "Processing member %d: buckets=%llu, bsectors=%d, bsize=%llu\n", dev->dev_idx, dev->mi.nbuckets, dev->mi.bucket_size, bsize_in_bytes);

		for (u64 bucket = 0, buckets_to_read = min(max(bsize_in_bytes, settings->scan_read_limit) / bsize_in_bytes, dev->mi.nbuckets);
				bucket < dev->mi.nbuckets;
				bucket += buckets_to_read, buckets_to_read = min(buckets_to_read, dev->mi.nbuckets - bucket)) {
			u64 read_size = bsize_in_bytes * buckets_to_read;

			void *data = vzalloc(read_size);
			if (!data) {
				printf("ERROR: unable to allocate memory for bucket data.\n");
				return -1;
			}

			struct bio *bio = bio_alloc_bioset(NULL, 1, REQ_OP_READ|REQ_SYNC, GFP_NOFS, &fs->bio_read);
			if (!bio) {
				printf("ERROR: unable to allocate BIO for read.\n");
				return -1;
			}
			bio_add_page(bio, vmalloc_to_page(data), read_size, 0);
			bio_set_dev(bio, dev->disk_sb.bdev);
			bio->bi_iter.bi_sector = bucket_to_sector(dev, bucket);
			submit_bio_wait(bio);

			if (bio->bi_status) {
				printf("ERROR: unexpected error while reading disk: %d\n", bio->bi_status);
				return -1;
			}

			void *data_iter = data;
			for (u64 i = 0; i < buckets_to_read; i++) {
				if (process_bucket(settings, dev, data_iter) < 0) {
					bio_put(bio);
					free(data);
					return -1;
				}
				data_iter += bsize_in_bytes;
			}

			bio_put(bio);
			free(data);
		}
	}

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
		{ "zero-fill", no_argument, NULL, 'z' },
		{ "use-last", no_argument, NULL, 'l' },
		{ "scan-bset", no_argument, NULL, 'B' },
		{ "scan-jset", no_argument, NULL, 'J' },
		{ "use-journal", no_argument, NULL, 'j' },
		{ "scan-read-limit", required_argument, NULL, 'm' },
		{ "include-inode", required_argument, NULL, 'i' },
		{ "exclude-inode", required_argument, NULL, 'I' },
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
		.zero_fill = false,
		.use_last = false,
		.scan_bset = false,
		.scan_jset = false,
		.use_journal = false,
		// Default limit of 1 GiB
		.scan_read_limit = (1 << 30),
		.included_inodes = {},
		.excluded_inodes = {},
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
	while ((opt = getopt_long(argc, argv, "t:s:e:czlBJjm:i:I:dvh", longopts, NULL)) != -1)
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
			settings.zero_fill = true;
			break;
		case 'l':
			settings.use_last = true;
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
	opt_set(opts, retain_recovery_info, true);
	opt_set(opts, read_journal_only, true);
	opt_set(opts, read_entire_journal, settings.use_journal);
	opt_set(opts, verbose, settings.verbose);

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
