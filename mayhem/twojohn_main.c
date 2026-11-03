/*
 * main() for zip2john, rar2john and gpg2john as standalone binaries (build with -DTOOL=<name>).
 * Upstream ships them as symlinks to run/john that dispatch on argv[0]; this calls the same
 * entry point without john's 38 MB start-up.
 */
#include "arch.h"
#include "params.h"
#include "options.h"

/* unicode.o (pulled in by rar2john) reads the global options; the rest of john is not linked. */
struct options_main options;

extern int TOOL(int argc, char **argv);

int main(int argc, char **argv)
{
	return TOOL(argc, argv);
}
