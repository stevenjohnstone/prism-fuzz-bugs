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
fuzz: src/util/pm_newline_list.c:51: _Bool pm_newline_list_append(pm_newline_list_t *, const uint8_t *): Assertion `list->size == 0 || newline_offset > list->offsets[list->size - 1]' failed.
AddressSanitizer:DEADLYSIGNAL
=================================================================
==75441==ERROR: AddressSanitizer: ABRT on unknown address 0x03e8000126b1 (pc 0xffff9a7a2008 bp 0xffffc3da5050 sp 0xffffc3da4fc0 T0)
    #0 0xffff9a7a2008 in __pthread_kill_implementation nptl/pthread_kill.c:44:76
    #1 0xffff9a75a838 in gsignal signal/../sysdeps/posix/raise.c:26:13
    #2 0xffff9a747130 in abort stdlib/abort.c:79:7
    #3 0xffff9a754110 in __assert_fail_base assert/assert.c:94:3
    #4 0xffff9a754188 in __assert_fail assert/assert.c:103:3
    #5 0xaaaab2f02134 in pm_newline_list_append /prism/src/util/pm_newline_list.c:51:5
    #6 0xaaaab2ebf1e4 in lex_embdoc /prism/src/prism.c:9329:9
    #7 0xaaaab2dc6080 in parser_lex /prism/src/prism.c:10279:48
    #8 0xaaaab2e17290 in parse_expression_prefix /prism/src/prism.c:19835:17
    #9 0xaaaab2dfed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaab2dfb804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaab2dbe274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaab2dbe274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaab2ed2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaab2f04320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaab2f044c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaab2d96034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaab2d95ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaab2d95988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffff9a7473fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffff9a7474d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaab2cbf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: ABRT nptl/pthread_kill.c:44:76 in __pthread_kill_implementation
==75441==ABORTING

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"            <<0;%r\n0\n\#{<<0}\n=begin\ne"
*/
static const uint8_t input[] = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x3c, 0x3c, 0x30, 0x3b, 0x25, 0x72, 0x0a, 0x30, 0x0a, 0x23, 0x7b, 0x3c,
    0x3c, 0x30, 0x7d, 0x0a, 0x3d, 0x62, 0x65, 0x67, 0x69, 0x6e, 0x0a, 0x65};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
