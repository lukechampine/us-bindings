#include <stdio.h>
#include <string.h>
#include "../us.h"

void decodeHex(uint8_t *out, char *hex) {
	while (*hex != 0) {
		sscanf(hex, "%2hhx", out++);
		hex += 2;
	}
}

void main() {
	// load contract
	//
	// fill in this string with a hex-encoded contract; it should be 192 bytes.
	// You can turn an existing contract into a hex string with the following
	// command:
	//     xxd -ps -s 12 -l 96 my.contract | tr -d '\n'
	char *contractHex = "<hex contract string>";
	uint8_t cdata[96];
	decodeHex(cdata, contractHex);
	contract_t c;
	us_contract_init(&c, cdata);

	// create host set with contract
	//
	// fill in this string with the address of any shard server
	char *shardAddr = "<shard server address>";
	void* hs = us_hostset_init(shardAddr);
	if (!hs) {
		puts(us_error());
		return;
	}
	if (!us_hostset_add(hs, &c)) {
		puts(us_error());
		return;
	}

	// create filesystem
	char *fs_root = "meta";
	void* fs = us_fs_init(fs_root, hs);

	// create a file
	int minHosts = 1;
	void *f = us_fs_create(fs, "foo.txt", minHosts);
	if (!f) {
		puts(us_error());
		goto closefs;
	}
	// write (upload) some data
	uint8_t data[] = "Hello from C!";
	ssize_t n = us_file_write(f, data, strlen(data));
	if (n == -1) {
		puts(us_error());
		us_file_close(f);
		goto closefs;
	}
	printf("Uploaded:  \t%s\n", data);

	// close the file
	if (!us_file_close(f)) {
		puts(us_error());
		goto closefs;
	}

	// reopen and read (download) the data
	f = us_fs_open(fs, "foo.txt");
	uint8_t buf[32];
	memset(buf, 0, sizeof(buf));
	n = us_file_read(f, buf, sizeof(buf));
	if (n == -1) {
		puts(us_error());
		us_file_close(f);
		goto closefs;
	}
	printf("Downloaded:\t%s\n", buf);

closefs:
	// close the filesystem
	if (!us_fs_close(fs)) {
		puts(us_error());
	}
}
