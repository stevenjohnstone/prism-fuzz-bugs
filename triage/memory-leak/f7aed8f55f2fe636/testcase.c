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
==7537==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaac62fde98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac649243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaac649243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaac649243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaac646a530 in pm_token_buffer_flush /prism/src/prism.c:9580:9
    #5 0xaaaac6372f7c in parser_lex /prism/src/prism.c
    #6 0xaaaac6401058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaac6402ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaac63f9114 in parse_pattern /prism/src/prism.c
    #9 0xaaaac63fd1fc in parse_pattern_hash /prism/src/prism.c:16509:25
    #10 0xaaaac63f8f0c in parse_pattern /prism/src/prism.c:16938:20
    #11 0xaaaac6400840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #12 0xaaaac6403318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #13 0xaaaac63f9114 in parse_pattern /prism/src/prism.c
    #14 0xaaaac63c96f4 in parse_expression_infix /prism/src/prism.c:21492:34
    #15 0xaaaac639f204 in parse_expression /prism/src/prism.c:21589:16
    #16 0xaaaac639b804 in parse_statements /prism/src/prism.c:13163:27
    #17 0xaaaac635e274 in parse_program /prism/src/prism.c:21810:40
    #18 0xaaaac635e274 in pm_parse /prism/src/prism.c:22242:12
    #19 0xaaaac6472800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #20 0xaaaac64a4320 in harness /prism/fuzz/parse.c:9:5
    #21 0xaaaac64a44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #22 0xaaaac6336034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #23 0xaaaac6335ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #24 0xaaaac6335988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #25 0xffff9e7973fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #26 0xffff9e7974d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #27 0xaaaac625f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"a=>{<<0\n00\\B00000000000000"
*/
static const uint8_t input[] = {0x61, 0x3d, 0x3e, 0x7b, 0x3c, 0x3c, 0x30,
                                0x0a, 0x30, 0x30, 0x5c, 0x42, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
