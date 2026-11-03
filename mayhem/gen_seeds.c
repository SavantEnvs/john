/*
 * One-off generator for mayhem/john_formats/testsuite: writes "<label>\n<ciphertext>" for the first
 * test vectors of every format.  Not built by build.sh; see the comment in mayhem/build.sh to
 * regenerate.  Link like fuzz_john_formats but with this file instead of the harness.
 */
#define main john_unused_main
#include "john.c"
#undef main

int main(int argc, char **argv)
{
	static char arg0[] = "/mayhem/run/john";
	static char arg1[] = "--test=0";
	static char *av[] = { arg0, arg1, NULL };
	struct fmt_main *f;
	unsigned int seq = 0;
	int i;

	if (argc < 2)
		return 1;
	path_init(av);
	john_init("john", 2, av);
	for (f = fmt_list; f; f = f->next) {
		if (!f->params.tests)
			continue;
		for (i = 0; i < 2 && f->params.tests[i].ciphertext; i++) {
			char path[4096];
			FILE *o;
			snprintf(path, sizeof(path), "%s/%s.%d", argv[1], f->params.label, i);
			if (!(o = fopen(path, "w")))
				return 2;
			struct fmt_tests *t = &f->params.tests[i];
			int k, last = -1;

			fprintf(o, "%s\n", f->params.label);
			if (t->fields[1]) {
				for (k = 0; k < 10; k++)
					if (t->fields[k])
						last = k;
				for (k = 0; k <= last; k++)
					fprintf(o, "%s%s", k ? ":" : "", t->fields[k] ? t->fields[k] : "");
			} else {
				fprintf(o, "%s%s%s", t->fields[0] ? t->fields[0] : "",
				        t->fields[0] ? ":" : "", t->ciphertext);
			}
			fclose(o);
			seq++;
		}
	}
	fprintf(stderr, "%u seeds\n", seq);
	return 0;
}
