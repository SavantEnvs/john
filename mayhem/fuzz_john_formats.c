/*
 * libFuzzer harness for john's hash-format front end: the prepare()/valid()/split()/get_salt()/
 * get_binary() path of every registered format, driven through ldr_load_pw_line() exactly like
 * upstream's `john --fuzz` mode (src/fuzz.c, built with --enable-fuzz).
 *
 * Input: "<format label>\n<password-file line>".  An unknown label selects a format by hashing it.
 */
#define main john_unused_main
#include "john.c"
#undef main

#include <signal.h>

#define MAX_LINE 0x30000

static struct fmt_main **tested;
static unsigned int ntested;

/* The encoding settings ldr_set_encoding() and initUnicode() write into the global options. */
static struct {
	int input_enc, default_enc, target_enc, default_target_enc, internal_cp, unicode_cp;
} saved_enc;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static char arg0[] = "/mayhem/run/john";
	static char arg1[] = "--test=0";
	static char *av[] = { arg0, arg1, NULL };
	struct fmt_main *format;
	unsigned int n = 0;
	size_t i;

	/* john_load() sets umask 077; it can only be read by setting it, so save it around john_init(). */
	mode_t old_umask = umask(0);

	umask(old_umask);
	path_init(av);
	john_init("john", 2, av);
	umask(old_umask);

	/*
	 * john_init() installs john's own SIGINT/SIGTERM/SIGXCPU/SIGXFSZ/SIGUSR1 handlers (sig_init(),
	 * sig_preinit()) and ignores SIGUSR2 and SIGHUP. libFuzzer never overrides a non-default
	 * handler, so they would keep it from handling interrupts and graceful-exit signals: restore
	 * the defaults so libFuzzer installs its own.
	 */
	{
		static const int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGXCPU, SIGXFSZ, SIGUSR1, SIGUSR2 };

		for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
			signal(sigs[i], SIG_DFL);
	}

	saved_enc.input_enc = options.input_enc;
	saved_enc.default_enc = options.default_enc;
	saved_enc.target_enc = options.target_enc;
	saved_enc.default_target_enc = options.default_target_enc;
	saved_enc.internal_cp = options.internal_cp;
	saved_enc.unicode_cp = options.unicode_cp;

	for (format = fmt_list; format; format = format->next)
		n++;
	tested = mem_alloc(n * sizeof(*tested));
	for (format = fmt_list; format; format = format->next)
		if (format->params.tests && format->methods.prepare &&
		    format->methods.valid && format->methods.split &&
		    format->methods.init)
			tested[ntested++] = format;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct db_main db;
	struct fmt_main *format = NULL;
	const uint8_t *nl;
	char label[64];
	size_t llen, i;
	unsigned int h = 2166136261u;
	char *line;

	if (size < 2 || size > MAX_LINE)
		return -1;
	nl = memchr(data, '\n', size);
	if (!nl || (llen = nl - data) >= sizeof(label))
		return -1;
	memcpy(label, data, llen);
	label[llen] = 0;

	for (i = 0; i < ntested; i++)
		if (!strcmp(tested[i]->params.label, label)) {
			format = tested[i];
			break;
		}
	if (!format) {
		for (i = 0; i < llen; i++)
			h = (h ^ (uint8_t)label[i]) * 16777619u;
		format = tested[h % ntested];
	}

	size -= llen + 1;
	line = malloc(size + 1);
	memcpy(line, nl + 1, size);
	line[size] = 0;

	ldr_set_encoding(format);
	fmt_init(format);
	ldr_init_database(&db, &options.loader);
	db.format = format;
	ldr_load_pw_line(&db, line);
	ldr_fix_database(&db);
	ldr_free_db(&db, 0);

	/* john leaves the format initialized: release it, and put back the encodings it chose. */
	fmt_done(format);
	options.input_enc = saved_enc.input_enc;
	options.default_enc = saved_enc.default_enc;
	options.target_enc = saved_enc.target_enc;
	options.default_target_enc = saved_enc.default_target_enc;
	options.internal_cp = saved_enc.internal_cp;
	options.unicode_cp = saved_enc.unicode_cp;
	free(line);
	return 0;
}
