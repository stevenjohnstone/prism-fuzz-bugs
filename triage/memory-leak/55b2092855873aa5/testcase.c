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
==9421==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 128 byte(s) in 1 object(s) allocated from:
    #0 0xaaaaaf1ede98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaaf38243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaaaf38243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaaaf38243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaaaf35c850 in pm_regexp_token_buffer_flush /prism/src/prism.c:9591:9
    #5 0xaaaaaf25f034 in parser_lex /prism/src/prism.c:11516:17
    #6 0xaaaaaf2f1058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaaaf2f2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaaaf2e9114 in parse_pattern /prism/src/prism.c
    #9 0xaaaaaf2b8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #10 0xaaaaaf28f204 in parse_expression /prism/src/prism.c:21589:16
    #11 0xaaaaaf28b804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaaaf24e274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaaaf24e274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaaaf362800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaaaf394320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaaaf3944c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaaaf226034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaaaf225ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaaaf225988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffffaadc73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffffaadc74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaaaf14f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 128 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in{/000\\c 0000000000000000000000000\n0"
*/
static const uint8_t input[] = {0x31, 0x69, 0x6e, 0x7b, 0x2f, 0x30, 0x30, 0x30,
                                0x5c, 0x63, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x0a, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
