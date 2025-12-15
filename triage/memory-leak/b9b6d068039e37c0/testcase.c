#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <prism.h>

__attribute__((noinline)) void harness(const uint8_t *input, size_t size) {
  pm_buffer_t buffer;
  pm_buffer_init(&buffer);
  pm_serialize_parse(&buffer, input, size, NULL);
  pm_buffer_free(&buffer);
}

/*

=================================================================
==66705==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 6 byte(s) in 2 object(s) allocated from:
    #0 0xaaaab49ddaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab4b71518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaab4a5c510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaab4a5c510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaab4a863dc in parse_expression_prefix /prism/src/prism.c:19525:25
    #5 0xaaaab4a7ed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaab4a7b804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaab4a9abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #8 0xaaaab4a7ed90 in parse_expression /prism/src/prism.c:21537:23
    #9 0xaaaab4a7b804 in parse_statements /prism/src/prism.c:13163:27
    #10 0xaaaab4a3e274 in parse_program /prism/src/prism.c:21810:40
    #11 0xaaaab4a3e274 in pm_parse /prism/src/prism.c:22242:12
    #12 0xaaaab4b52800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #13 0xaaaab4b84320 in harness /prism/fuzz/parse.c:9:5
    #14 0xaaaab4b844c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #15 0xaaaab4a16034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #16 0xaaaab4a15ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #17 0xaaaab4a15988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #18 0xffffa1f073fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #19 0xffffa1f074d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #20 0xaaaab493f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 6 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"def.%I \#{end ?\\ >?\\e"
*/
static const uint8_t input[] = {0x64, 0x65, 0x66, 0x2e, 0x25, 0x49, 0x20,
                                0x23, 0x7b, 0x65, 0x6e, 0x64, 0x20, 0x3f,
                                0x5c, 0x20, 0x3e, 0x3f, 0x5c, 0x65};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
