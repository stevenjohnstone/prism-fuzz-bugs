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
==21644==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 96 byte(s) in 2 object(s) allocated from:
    #0 0xaaaad6a1dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad6b12af0 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaad6b12af0 in pm_block_argument_node_create /prism/src/prism.c:2395:38
    #3 0xaaaad6b12af0 in parse_arguments /prism/src/prism.c:13487:28
    #4 0xaaaad6ac986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #5 0xaaaad6abed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaad6abb804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaad6adabf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #8 0xaaaad6abed90 in parse_expression /prism/src/prism.c:21537:23
    #9 0xaaaad6af0db8 in parse_value_expression /prism/src/prism.c:12430:23
    #10 0xaaaad6af0db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #11 0xaaaad6af0db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #12 0xaaaad6aecc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #13 0xaaaad6abf204 in parse_expression /prism/src/prism.c:21589:16
    #14 0xaaaad6abb804 in parse_statements /prism/src/prism.c:13163:27
    #15 0xaaaad6a7e274 in parse_program /prism/src/prism.c:21810:40
    #16 0xaaaad6a7e274 in pm_parse /prism/src/prism.c:22242:12
    #17 0xaaaad6b92800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #18 0xaaaad6bc4320 in harness /prism/fuzz/parse.c:9:5
    #19 0xaaaad6bc44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #20 0xaaaad6a56034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #21 0xaaaad6a55ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #22 0xaaaad6a55988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #23 0xffff942373fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #24 0xffff942374d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #25 0xaaaad697f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Indirect leak of 272 byte(s) in 2 object(s) allocated from:
    #0 0xaaaad6a1dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad6b5e9f4 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaad6b5e9f4 in pm_call_node_create /prism/src/prism.c:2561:28
    #3 0xaaaad6b5e9f4 in pm_call_node_variable_call_create /prism/src/prism.c:2815:28
    #4 0xaaaad6acee50 in parse_variable_call /prism/src/prism.c:15775:28
    #5 0xaaaad6acee50 in parse_expression_prefix /prism/src/prism.c:17885:31
    #6 0xaaaad6abed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaad6b101ac in parse_value_expression /prism/src/prism.c:12430:23
    #8 0xaaaad6b101ac in parse_arguments /prism/src/prism.c:13482:34
    #9 0xaaaad6ac986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #10 0xaaaad6abed90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaad6abb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaad6adabf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #13 0xaaaad6abed90 in parse_expression /prism/src/prism.c:21537:23
    #14 0xaaaad6af0db8 in parse_value_expression /prism/src/prism.c:12430:23
    #15 0xaaaad6af0db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #16 0xaaaad6af0db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #17 0xaaaad6aecc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #18 0xaaaad6abf204 in parse_expression /prism/src/prism.c:21589:16
    #19 0xaaaad6abb804 in parse_statements /prism/src/prism.c:13163:27
    #20 0xaaaad6a7e274 in parse_program /prism/src/prism.c:21810:40
    #21 0xaaaad6a7e274 in pm_parse /prism/src/prism.c:22242:12
    #22 0xaaaad6b92800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #23 0xaaaad6bc4320 in harness /prism/fuzz/parse.c:9:5
    #24 0xaaaad6bc44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #25 0xaaaad6a56034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #26 0xaaaad6a55ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #27 0xaaaad6a55988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #28 0xffff942373fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #29 0xffff942374d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #30 0xaaaad697f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 368 byte(s) leaked in 4 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"def s return o,&s return o,& "
*/
static const uint8_t input[] = {0x64, 0x65, 0x66, 0x20, 0x73, 0x20, 0x72, 0x65,
                                0x74, 0x75, 0x72, 0x6e, 0x20, 0x6f, 0x2c, 0x26,
                                0x73, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e,
                                0x20, 0x6f, 0x2c, 0x26, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
