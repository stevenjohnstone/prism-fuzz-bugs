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
==29257==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 3 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad7ecdaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad8061518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaad7f4c510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaad7f4c510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaad7f7884c in parse_expression_prefix /prism/src/prism.c:20110:13
    #5 0xaaaad7f6ed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaad7f6b804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaad7feb46c in parse_rescues /prism/src/prism.c:14397:48
    #8 0xaaaad8019208 in parse_rescues_implicit_begin /prism/src/prism.c:14518:5
    #9 0xaaaad7f87a4c in parse_expression_prefix /prism/src/prism.c:18536:34
    #10 0xaaaad7f6ed90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaad7f6b804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaad7feb46c in parse_rescues /prism/src/prism.c:14397:48
    #13 0xaaaad8019208 in parse_rescues_implicit_begin /prism/src/prism.c:14518:5
    #14 0xaaaad7f87a4c in parse_expression_prefix /prism/src/prism.c:18536:34
    #15 0xaaaad7f6ed90 in parse_expression /prism/src/prism.c:21537:23
    #16 0xaaaad7f6b804 in parse_statements /prism/src/prism.c:13163:27
    #17 0xaaaad7f2e274 in parse_program /prism/src/prism.c:21810:40
    #18 0xaaaad7f2e274 in pm_parse /prism/src/prism.c:22242:12
    #19 0xaaaad8042800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #20 0xaaaad8074320 in harness /prism/fuzz/parse.c:9:5
    #21 0xaaaad80744c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #22 0xaaaad7f06034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #23 0xaaaad7f05ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #24 0xaaaad7f05988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #25 0xffffa16173fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #26 0xffffa16174d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #27 0xaaaad7e2f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 3 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"class e class rescue g:?\\i"
*/
static const uint8_t input[] = {0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x65,
                                0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20,
                                0x72, 0x65, 0x73, 0x63, 0x75, 0x65, 0x20,
                                0x67, 0x3a, 0x3f, 0x5c, 0x69};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
