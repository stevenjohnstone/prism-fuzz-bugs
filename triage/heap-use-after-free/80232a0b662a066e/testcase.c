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
==52488==ERROR: AddressSanitizer: heap-use-after-free on address 0x604000000450 at pc 0xaaaace35e754 bp 0xffffe96601f0 sp 0xffffe96601e8
READ of size 2 at 0x604000000450 thread T0
    #0 0xaaaace35e750 in flush_block_exits /prism/src/prism.c:15044:17
    #1 0xaaaace35e750 in parse_program /prism/src/prism.c:21829:9
    #2 0xaaaace35e750 in pm_parse /prism/src/prism.c:22242:12
    #3 0xaaaace472800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #4 0xaaaace4a4320 in harness /prism/fuzz/parse.c:9:5
    #5 0xaaaace4a44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #6 0xaaaace336034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #7 0xaaaace335ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #8 0xaaaace335988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #9 0xffff8cc273fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #10 0xffff8cc274d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #11 0xaaaace25f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

0x604000000450 is located 0 bytes inside of 48-byte region [0x604000000450,0x604000000480)
freed by thread T0 here:
    #0 0xaaaace2fd80c in free (/prism/build/fuzz+0x17d80c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaace3542b4 in pm_node_list_destroy /prism/prism/templates/src/node.c.erb:96:45
    #2 0xaaaace3524d0 in pm_node_destroy /prism/prism/templates/src/node.c.erb:112:13
    #3 0xaaaace352614 in pm_node_destroy /prism/prism/templates/src/node.c.erb:116:17
    #4 0xaaaace350b48 in pm_node_destroy /prism/prism/templates/src/node.c.erb:113:17
    #5 0xaaaace400228 in parse_pattern_primitive /prism/src/prism.c:16689:17
    #6 0xaaaace402ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #7 0xaaaace3f9114 in parse_pattern /prism/src/prism.c
    #8 0xaaaace3c8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #9 0xaaaace39f204 in parse_expression /prism/src/prism.c:21589:16
    #10 0xaaaace39b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaace35e274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaace35e274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaace472800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaace4a4320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaace4a44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaace336034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaace335ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaace335988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffff8cc273fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffff8cc274d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaace25f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

previously allocated by thread T0 here:
    #0 0xaaaace2fdc7c in calloc (/prism/build/fuzz+0x17dc7c) (BuildId: 27a80e0520a7c276)
    #1 0xaaaace446680 in pm_node_alloc /prism/src/prism.c:1934:20
    #2 0xaaaace446680 in pm_break_node_create /prism/src/prism.c:2530:29
    #3 0xaaaace3b0ea8 in parse_expression_prefix /prism/src/prism.c:18449:39
    #4 0xaaaace39ed90 in parse_expression /prism/src/prism.c:21537:23
    #5 0xaaaace3aa218 in parse_expression_prefix /prism/src/prism.c:19990:39
    #6 0xaaaace39ed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaace3fffb8 in parse_pattern_primitive /prism/src/prism.c:16680:31
    #8 0xaaaace402ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #9 0xaaaace3f9114 in parse_pattern /prism/src/prism.c
    #10 0xaaaace3c8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #11 0xaaaace39f204 in parse_expression /prism/src/prism.c:21589:16
    #12 0xaaaace39b804 in parse_statements /prism/src/prism.c:13163:27
    #13 0xaaaace35e274 in parse_program /prism/src/prism.c:21810:40
    #14 0xaaaace35e274 in pm_parse /prism/src/prism.c:22242:12
    #15 0xaaaace472800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #16 0xaaaace4a4320 in harness /prism/fuzz/parse.c:9:5
    #17 0xaaaace4a44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #18 0xaaaace336034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #19 0xaaaace335ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #20 0xaaaace335988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #21 0xffff8cc273fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #22 0xffff8cc274d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #23 0xaaaace25f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: heap-use-after-free /prism/src/prism.c:15044:17 in flush_block_exits
Shadow bytes around the buggy address:
  0x604000000180: fa fa 00 00 00 00 00 00 fa fa fd fd fd fd fd fd
  0x604000000200: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 00
  0x604000000280: fa fa 00 00 00 00 06 fa fa fa 00 00 00 00 00 00
  0x604000000300: fa fa 00 00 00 00 00 00 fa fa fd fd fd fd fd fd
  0x604000000380: fa fa fd fd fd fd fd fd fa fa 00 00 00 00 00 00
=>0x604000000400: fa fa 00 00 00 00 00 03 fa fa[fd]fd fd fd fd fd
  0x604000000480: fa fa 00 00 00 00 00 00 fa fa fd fd fd fd fd fd
  0x604000000500: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 00
  0x604000000580: fa fa 00 00 00 00 00 02 fa fa 00 00 00 00 00 00
  0x604000000600: fa fa 00 00 00 00 00 02 fa fa fa fa fa fa fa fa
  0x604000000680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==52488==ABORTING

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"2in-0**break "
*/
static const uint8_t input[] = {0x32, 0x69, 0x6e, 0x2d, 0x30, 0x2a, 0x2a,
                                0x62, 0x72, 0x65, 0x61, 0x6b, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
