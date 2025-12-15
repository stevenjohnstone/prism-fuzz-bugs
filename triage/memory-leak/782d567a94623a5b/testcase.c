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
==91407==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 6 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad98ade98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad9a4243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad9a4243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad9a4243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaad9a1f524 in escape_write_escape_encoded /prism/src/prism.c:8725:9
    #5 0xaaaad992c524 in lex_question_mark /prism/src/prism.c:9226:9
    #6 0xaaaad992c524 in parser_lex /prism/src/prism.c:10502:21
    #7 0xaaaad99c6144 in parse_string_part /prism/src/prism.c:15452:13
    #8 0xaaaad99677a0 in parse_expression_prefix /prism/src/prism.c:19902:29
    #9 0xaaaad994ed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaad994b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaad9968290 in parse_expression_prefix /prism/src/prism.c:19001:48
    #12 0xaaaad994ed90 in parse_expression /prism/src/prism.c:21537:23
    #13 0xaaaad994b804 in parse_statements /prism/src/prism.c:13163:27
    #14 0xaaaad990e274 in parse_program /prism/src/prism.c:21810:40
    #15 0xaaaad990e274 in pm_parse /prism/src/prism.c:22242:12
    #16 0xaaaad9a22800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #17 0xaaaad9a54320 in harness /prism/fuzz/parse.c:9:5
    #18 0xaaaad9a544c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #19 0xaaaad98e6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #20 0xaaaad98e5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #21 0xaaaad98e5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #22 0xffffabbf73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #23 0xffffabbf74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #24 0xaaaad980f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 6 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
".`?\\\u{3930A}"
*/
static const uint8_t input[] = {0x2e, 0x60, 0x3f, 0x5c, 0xf0, 0xb9, 0x8c, 0x8a};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
