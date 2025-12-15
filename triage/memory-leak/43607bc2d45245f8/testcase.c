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
==4934==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaaad87de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaada1243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaaada1243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaaada1243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaaad8ed798 in parser_lex /prism/src/prism.c:11457:33
    #5 0xaaaaad981058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #6 0xaaaaad982ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #7 0xaaaaad979114 in parse_pattern /prism/src/prism.c
    #8 0xaaaaad948684 in parse_expression_infix /prism/src/prism.c:21475:34
    #9 0xaaaaad91f204 in parse_expression /prism/src/prism.c:21589:16
    #10 0xaaaaad91b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaaad8de274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaaad8de274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaaad9f2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaaada24320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaaada244c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaaad8b6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaaad8b5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaaad8b5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffffa71b73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffffa71b74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaaad7df22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in{/\\u{              "
*/
static const uint8_t input[] = {0x31, 0x69, 0x6e, 0x7b, 0x2f, 0x5c, 0x75, 0x7b,
                                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
