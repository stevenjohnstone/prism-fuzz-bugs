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
==26526==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000520 at pc 0xaaaab30bf2fc bp 0xfffff16f3cf0 sp 0xfffff16f3ce8
READ of size 2 at 0x603000000520 thread T0
    #0 0xaaaab30bf2f8 in parse_blocklike_parameters /prism/src/prism.c:14663:13
    #1 0xaaaab3096e94 in parse_block /prism/src/prism.c:14759:29
    #2 0xaaaab3088970 in parse_arguments_list /prism/src/prism.c:14822:21
    #3 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #4 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #5 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #6 0xaaaab30969c0 in parse_block /prism/src/prism.c:14736:26
    #7 0xaaaab3088970 in parse_arguments_list /prism/src/prism.c:14822:21
    #8 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #9 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaab30901ac in parse_value_expression /prism/src/prism.c:12430:23
    #11 0xaaaab30901ac in parse_arguments /prism/src/prism.c:13482:34
    #12 0xaaaab30890b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #13 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #14 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #15 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #16 0xaaaab305abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #17 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #18 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #19 0xaaaab2ffe274 in parse_program /prism/src/prism.c:21810:40
    #20 0xaaaab2ffe274 in pm_parse /prism/src/prism.c:22242:12
    #21 0xaaaab3112800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #22 0xaaaab3144320 in harness /prism/fuzz/parse.c:9:5
    #23 0xaaaab31444c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #24 0xaaaab2fd6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #25 0xaaaab2fd5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #26 0xaaaab2fd5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #27 0xffffa60273fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #28 0xffffa60274d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #29 0xaaaab2eff22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

0x603000000520 is located 0 bytes inside of 24-byte region [0x603000000520,0x603000000538)
freed by thread T0 here:
    #0 0xaaaab2f9d80c in free (/prism/build/fuzz+0x17d80c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab2ff42b4 in pm_node_list_destroy /prism/prism/templates/src/node.c.erb:96:45
    #2 0xaaaab2ff24d0 in pm_node_destroy /prism/prism/templates/src/node.c.erb:112:13
    #3 0xaaaab2ff2614 in pm_node_destroy /prism/prism/templates/src/node.c.erb:116:17
    #4 0xaaaab2ff0b48 in pm_node_destroy /prism/prism/templates/src/node.c.erb:113:17
    #5 0xaaaab30a0228 in parse_pattern_primitive /prism/src/prism.c:16689:17
    #6 0xaaaab30a2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #7 0xaaaab3099114 in parse_pattern /prism/src/prism.c
    #8 0xaaaab3068684 in parse_expression_infix /prism/src/prism.c:21475:34
    #9 0xaaaab303f204 in parse_expression /prism/src/prism.c:21589:16
    #10 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaab30969c0 in parse_block /prism/src/prism.c:14736:26
    #12 0xaaaab3088970 in parse_arguments_list /prism/src/prism.c:14822:21
    #13 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #14 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #15 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #16 0xaaaab30969c0 in parse_block /prism/src/prism.c:14736:26
    #17 0xaaaab3088970 in parse_arguments_list /prism/src/prism.c:14822:21
    #18 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #19 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #20 0xaaaab30901ac in parse_value_expression /prism/src/prism.c:12430:23
    #21 0xaaaab30901ac in parse_arguments /prism/src/prism.c:13482:34
    #22 0xaaaab30890b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #23 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #24 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #25 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #26 0xaaaab305abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #27 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #28 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #29 0xaaaab2ffe274 in parse_program /prism/src/prism.c:21810:40
    #30 0xaaaab2ffe274 in pm_parse /prism/src/prism.c:22242:12
    #31 0xaaaab3112800 in pm_serialize_parse /prism/src/prism.c:22410:23

previously allocated by thread T0 here:
    #0 0xaaaab2f9dc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab30ac590 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaab30ac590 in pm_it_local_variable_read_node_create /prism/src/prism.c:4992:46
    #3 0xaaaab30a77e8 in parse_variable /prism/src/prism.c:15752:31
    #4 0xaaaab304f304 in parse_variable_call /prism/src/prism.c:15770:27
    #5 0xaaaab304f304 in parse_expression_prefix /prism/src/prism.c:17885:31
    #6 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaab304a218 in parse_expression_prefix /prism/src/prism.c:19990:39
    #8 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #9 0xaaaab309ffb8 in parse_pattern_primitive /prism/src/prism.c:16680:31
    #10 0xaaaab30a2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #11 0xaaaab3099114 in parse_pattern /prism/src/prism.c
    #12 0xaaaab3068684 in parse_expression_infix /prism/src/prism.c:21475:34
    #13 0xaaaab303f204 in parse_expression /prism/src/prism.c:21589:16
    #14 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #15 0xaaaab30969c0 in parse_block /prism/src/prism.c:14736:26
    #16 0xaaaab3088970 in parse_arguments_list /prism/src/prism.c:14822:21
    #17 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #18 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #19 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #20 0xaaaab30969c0 in parse_block /prism/src/prism.c:14736:26
    #21 0xaaaab3088970 in parse_arguments_list /prism/src/prism.c:14822:21
    #22 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #23 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #24 0xaaaab30901ac in parse_value_expression /prism/src/prism.c:12430:23
    #25 0xaaaab30901ac in parse_arguments /prism/src/prism.c:13482:34
    #26 0xaaaab30890b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #27 0xaaaab304ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #28 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #29 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27
    #30 0xaaaab305abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #31 0xaaaab303ed90 in parse_expression /prism/src/prism.c:21537:23
    #32 0xaaaab303b804 in parse_statements /prism/src/prism.c:13163:27

SUMMARY: AddressSanitizer: heap-use-after-free /prism/src/prism.c:14663:13 in parse_blocklike_parameters
Shadow bytes around the buggy address:
  0x603000000280: 00 00 00 00 fa fa 00 00 00 fa fa fa 00 00 00 04
  0x603000000300: fa fa 00 00 00 fa fa fa 00 00 00 fa fa fa fd fd
  0x603000000380: fd fd fa fa 00 00 00 00 fa fa fd fd fd fd fa fa
  0x603000000400: 00 00 00 00 fa fa 00 00 00 00 fa fa 00 00 00 00
  0x603000000480: fa fa 00 00 00 00 fa fa 00 00 00 00 fa fa fd fd
=>0x603000000500: fd fd fa fa[fd]fd fd fa fa fa fd fd fd fd fa fa
  0x603000000580: 00 00 00 fa fa fa 00 00 00 fa fa fa 00 00 00 00
  0x603000000600: fa fa 00 00 00 fa fa fa 00 00 00 00 fa fa fa fa
  0x603000000680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x603000000700: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x603000000780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==26526==ABORTING

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"L{b{9in-2**it  "
*/
static const uint8_t input[] = {0x4c, 0x7b, 0x62, 0x7b, 0x39, 0x69, 0x6e, 0x2d,
                                0x32, 0x2a, 0x2a, 0x69, 0x74, 0x20, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
