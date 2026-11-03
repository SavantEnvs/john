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

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static char arg0[] = "/mayhem/run/john";
	static char arg1[] = "--test=0";
	static char *av[] = { arg0, arg1, NULL };
	struct fmt_main *format;
	unsigned int n = 0;
	size_t i;

	path_init(av);
	john_init("john", 2, av);

	/*
	 * john_init() installs john's own SIGINT/SIGTERM/SIGXCPU/SIGXFSZ/SIGUSR1 handlers (sig_init(),
	 * sig_preinit()) and ignores SIGUSR2. libFuzzer never overrides a non-default handler, so they
	 * would keep it from handling interrupts and graceful-exit signals: restore the defaults so
	 * libFuzzer installs its own.
	 */
	{
		static const int sigs[] = { SIGINT, SIGTERM, SIGXCPU, SIGXFSZ, SIGUSR1, SIGUSR2 };

		for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
			signal(sigs[i], SIG_DFL);
	}

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
	free(line);
	return 0;
}
