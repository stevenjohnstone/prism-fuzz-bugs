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
==401==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 48 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab382dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab3922af0 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaab3922af0 in pm_block_argument_node_create /prism/src/prism.c:2395:38
    #3 0xaaaab3922af0 in parse_arguments /prism/src/prism.c:13487:28
    #4 0xaaaab38d986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #5 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaab38cb804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaab388e274 in parse_program /prism/src/prism.c:21810:40
    #8 0xaaaab388e274 in pm_parse /prism/src/prism.c:22242:12
    #9 0xaaaab39a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #10 0xaaaab39d4320 in harness /prism/fuzz/parse.c:9:5
    #11 0xaaaab39d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #12 0xaaaab3866034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #13 0xaaaab3865ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #14 0xaaaab3865988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #15 0xffff842573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #16 0xffff842574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #17 0xaaaab378f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Indirect leak of 136 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab382dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab396e9f4 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaab396e9f4 in pm_call_node_create /prism/src/prism.c:2561:28
    #3 0xaaaab396e9f4 in pm_call_node_variable_call_create /prism/src/prism.c:2815:28
    #4 0xaaaab38dee50 in parse_variable_call /prism/src/prism.c:15775:28
    #5 0xaaaab38dee50 in parse_expression_prefix /prism/src/prism.c:17885:31
    #6 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaab39201ac in parse_value_expression /prism/src/prism.c:12430:23
    #8 0xaaaab39201ac in parse_arguments /prism/src/prism.c:13482:34
    #9 0xaaaab38d986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #10 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaab38cb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaab388e274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaab388e274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaab39a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaab39d4320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaab39d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaab3866034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaab3865ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaab3865988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffff842573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffff842574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaab378f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Indirect leak of 136 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab382dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab3917378 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaab3917378 in pm_call_node_create /prism/src/prism.c:2561:28
    #3 0xaaaab3917378 in pm_call_node_binary_create /prism/src/prism.c:2627:28
    #4 0xaaaab38f9bb0 in parse_expression_infix /prism/src/prism.c
    #5 0xaaaab38cf204 in parse_expression /prism/src/prism.c:21589:16
    #6 0xaaaab39201ac in parse_value_expression /prism/src/prism.c:12430:23
    #7 0xaaaab39201ac in parse_arguments /prism/src/prism.c:13482:34
    #8 0xaaaab38d986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #9 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaab38cb804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaab388e274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaab388e274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaab39a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaab39d4320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaab39d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaab3866034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaab3865ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaab3865988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffff842573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffff842574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaab378f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Indirect leak of 48 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab382dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab3917624 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaab3917624 in pm_arguments_node_create /prism/src/prism.c:2051:33
    #3 0xaaaab3917624 in pm_call_node_binary_create /prism/src/prism.c:2635:38
    #4 0xaaaab38f9bb0 in parse_expression_infix /prism/src/prism.c
    #5 0xaaaab38cf204 in parse_expression /prism/src/prism.c:21589:16
    #6 0xaaaab39201ac in parse_value_expression /prism/src/prism.c:12430:23
    #7 0xaaaab39201ac in parse_arguments /prism/src/prism.c:13482:34
    #8 0xaaaab38d986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #9 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaab38cb804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaab388e274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaab388e274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaab39a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaab39d4320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaab39d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaab3866034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaab3865ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaab3865988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffff842573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffff842574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaab378f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Indirect leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab382de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab388040c in pm_node_list_grow /prism/prism/templates/src/node.c.erb:35:40
    #2 0xaaaab388040c in pm_node_list_append /prism/prism/templates/src/node.c.erb:48:9
    #3 0xaaaab39177bc in pm_arguments_node_arguments_append /prism/src/prism.c:2082:5
    #4 0xaaaab39177bc in pm_call_node_binary_create /prism/src/prism.c:2636:5
    #5 0xaaaab38f9bb0 in parse_expression_infix /prism/src/prism.c
    #6 0xaaaab38cf204 in parse_expression /prism/src/prism.c:21589:16
    #7 0xaaaab39201ac in parse_value_expression /prism/src/prism.c:12430:23
    #8 0xaaaab39201ac in parse_arguments /prism/src/prism.c:13482:34
    #9 0xaaaab38d986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #10 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaab38cb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaab388e274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaab388e274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaab39a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaab39d4320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaab39d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaab3866034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaab3865ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaab3865988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffff842573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffff842574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaab378f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Indirect leak of 24 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab382dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab38d048c in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaab38d048c in pm_missing_node_create /prism/src/prism.c:1965:31
    #3 0xaaaab38e6dc0 in parse_expression_prefix /prism/src/prism.c
    #4 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #5 0xaaaab38f9b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #6 0xaaaab38cf204 in parse_expression /prism/src/prism.c:21589:16
    #7 0xaaaab39201ac in parse_value_expression /prism/src/prism.c:12430:23
    #8 0xaaaab39201ac in parse_arguments /prism/src/prism.c:13482:34
    #9 0xaaaab38d986c in parse_expression_prefix /prism/src/prism.c:18438:21
    #10 0xaaaab38ced90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaab38cb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaab388e274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaab388e274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaab39a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaab39d4320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaab39d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaab3866034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaab3865ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaab3865988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffff842573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffff842574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaab378f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 424 byte(s) leaked in 6 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"return 1,& "
*/
static const uint8_t input[] = {0x72, 0x65, 0x74, 0x75, 0x72, 0x6e,
                                0x20, 0x31, 0x2c, 0x26, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
