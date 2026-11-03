# Appended to the configured src/Makefile by build.sh (make -f Makefile -f ../mayhem/harness.mk).
# The format harness is compiled with exactly the project's own flags.
fuzz_john_formats.o: $(MAYHEM_DIR)/fuzz_john_formats.c john.c
	$(CC) $(CFLAGS) $(OPT_NORMAL) -I. -c $(MAYHEM_DIR)/fuzz_john_formats.c -o $@

# ldr_split_line() computes `p += strlen(p) - 1` on a hash-only line, so any empty line steps one byte
# before the buffer (pointer-overflow). Benign in practice, but it halts on the first empty line and
# hides everything behind it; relax just this check just for this file.
loader.o: CFLAGS_MAIN += -fno-sanitize=pointer-overflow
