/* Embedded SWI-Prolog libFuzzer harness.
 *
 * Compiled once per target with -DFUZZ_PRED="fuzz_<t>" and -DFUZZ_ENC=<IOENC>. The Prolog system is
 * initialised once (PL_initialise cannot be re-run in a process); mayhem/harnesses/fuzz.pl is then
 * consulted, which defines one driver predicate per target. Each input is handed to the driver as a
 * read-only Prolog input stream over an exact-size copy of the bytes (Sopen_string), decoded with
 * FUZZ_ENC (octets for the binary inputs, ISO-Latin-1
 * for the op-script targets). The driver closes the
 * stream; everything it creates is scoped to the call (temporary modules, tries it destroys).
 *
 * Runtime files: the Prolog home (boot.prc + library) built by mayhem/build.sh at build/fuzz/home,
 * and the driver, both located relative to this executable (installed at the repo root).
 */
#include <SWI-Stream.h>
#include <SWI-Prolog.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FUZZ_PRED
#error "define FUZZ_PRED"
#endif
#ifndef FUZZ_ENC
#define FUZZ_ENC ENC_UTF8
#endif

static predicate_t driver;

static void die(const char *msg) {
  fprintf(stderr, "fuzz_swipl: %s\n", msg);
  abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  static char exe[PATH_MAX], home[PATH_MAX + 32], script[PATH_MAX + 64];
  ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (n <= 0) die("cannot resolve /proc/self/exe");
  exe[n] = 0;
  char *dir = dirname(exe);
  snprintf(home, sizeof(home), "--home=%s/build/fuzz/home", dir);
  snprintf(script, sizeof(script), "%s/mayhem/harnesses/fuzz.pl", dir);

  char *av[] = {(*argv)[0], home, "-q", "--no-signals", "--no-packs",
                "--no-threads", "-f", "none", "--stack-limit=256m", NULL};
  if (!PL_initialise((int)(sizeof(av) / sizeof(av[0])) - 1, av))
    die("PL_initialise failed");

  fid_t fid = PL_open_foreign_frame();
  term_t a = PL_new_term_ref();
  if (!PL_put_atom_chars(a, script) ||
      !PL_call_predicate(NULL, PL_Q_NORMAL, PL_predicate("consult", 1, "user"), a))
    die("cannot load mayhem/harnesses/fuzz.pl");
  PL_discard_foreign_frame(fid);

  driver = PL_predicate(FUZZ_PRED, 1, "user");
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* exact-size heap copy so ASan sees any read past the input */
  char *buf = malloc(size ? size : 1);
  if (!buf) return 0;
  memcpy(buf, data, size);

  IOSTREAM *in = Sopen_string(NULL, buf, size, "r");
  if (!in) { free(buf); return 0; }
  Ssetenc(in, FUZZ_ENC, NULL);

  fid_t fid = PL_open_foreign_frame();
  term_t t = PL_new_term_ref();
  if (PL_unify_stream(t, in)) {
    /* the driver closes the stream on every path (setup_call_cleanup) */
    PL_call_predicate(NULL, PL_Q_NODEBUG | PL_Q_CATCH_EXCEPTION, driver, t);
    PL_clear_exception();
  } else {
    Sclose(in);
  }
  PL_discard_foreign_frame(fid);
  free(buf);
  return 0;
}
