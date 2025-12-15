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
==88806==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 3 byte(s) in 1 object(s) allocated from:
    #0 0xaaaacd75daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaacd8f1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaacd7dc510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaacd7dc510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaacd84b31c in accept1 /prism/src/prism.c:12350:9
    #5 0xaaaacd84b31c in parse_targets_validate /prism/src/prism.c:13134:5
    #6 0xaaaacd818bb4 in parse_expression_prefix /prism/src/prism.c:17950:24
    #7 0xaaaacd7fed90 in parse_expression /prism/src/prism.c:21537:23
    #8 0xaaaacd7fb804 in parse_statements /prism/src/prism.c:13163:27
    #9 0xaaaacd7be274 in parse_program /prism/src/prism.c:21810:40
    #10 0xaaaacd7be274 in pm_parse /prism/src/prism.c:22242:12
    #11 0xaaaacd8d2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #12 0xaaaacd904320 in harness /prism/fuzz/parse.c:9:5
    #13 0xaaaacd9044c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #14 0xaaaacd796034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #15 0xaaaacd795ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #16 0xaaaacd795988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #17 0xffff91ff73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #18 0xffff91ff74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #19 0xaaaacd6bf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 3 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"  f{{1},   b\n?\\b"
*/
static const uint8_t input[] = {0x20, 0x20, 0x66, 0x7b, 0x7b, 0x31, 0x7d, 0x2c,
                                0x20, 0x20, 0x20, 0x62, 0x0a, 0x3f, 0x5c, 0x62};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
