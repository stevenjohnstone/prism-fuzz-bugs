# Prism Fuzzing Bugs

This repo contains fuzzing bugs from a campaign running against https://github.com/ruby/prism/commit/fde821aa33fe995d93e189ff98a06dcaffa5843a.

In [fuzz-coverage-report](./fuzz-coverage-report) is an html coverage overview from the fuzz campaign. See https://stevenjohnstone.github.io/prism-fuzz-bugs/.

In [triage](./triage) are testcases demonstrating various issues. The issues are categorized under [ABRT](./triage/ABRT) (for assertion failures),
[heap-use-after-free](./triage/heap-use-after-free) and [memory-leak](./triage/memory-leak). Under each directory are
best-effort deduplications of hopefully distinct bugs. Two bugs are considered to be the same if 
1. they are of the same bug class, and
2. a truncation of the ASAN/MSAN report with randomized elements removed (e.g. heap addresses) gives the same result for the two bugs.

From eye-balling the memory-leak testcases, I suspect that a few have common root causes.


To reproduce bugs
1. Checkout this repo into a checkout of the prism source in the sub-directory, say, `fuzz-bugs`
2. With docker running, execute `make fuzz-debug`
3. In the docker shell, build a testcase with `./fuzz-bugs/build.sh <path to testcase.c>`
4. Run `./testcase`

If your platform doesn't support address/leak sanitizers but you have docker, you can build and debug
test cases by running `make fuzz-debug` in the prism respository and the instructions above should
work with no issues.

## Random Observations

- it's worth building test cases without sanitizers to see if an assertion fails in normal use cases
