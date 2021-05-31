# defined in llvm/projects/compiler-rt/lib/fuzzer/FuzzerInterface.h
## NOTE: the libFuzzer interface is thin and in the majority of cases
## you should not include this file into your target. In 95% of cases
## all you need is to define the procedure `testOneInput` in your file.

proc initialize: cint {.exportc: "LLVMFuzzerInitialize".} = discard "to implement"
  ## Optional user-provided initialization procedure.
  ## If provided, this procedure will be called by libFuzzer once at startup.
  ## Must return 0.

proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} = discard "to implement"
  ## Mandatory user-provided target procedure.
  ## Executes the code under test with `data` as the input.
  ## libFuzzer will invoke this procedure *many* times with different inputs.
  ## Must return 0.

proc customMutator(data: var openarray[byte], maxLen: int, seed: int64): cint {.
    exportc: "LLVMFuzzerCustomMutator".} = discard "to implement"
  ## Optional user-provided custom mutator.
  ## Mutates raw data in `data` inplace.
  ## Returns the new length, which is not greater than `maxLen`.
  ## Given the same `seed` produces the same mutation.

proc customCrossOver(data1: openarray[byte], data2: openarray[byte],
    res: var openarray[byte], maxOutLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomCrossOver".} = discard "to implement"
  ## Optional user-provided custom cross-over procedure.
  ## Combines pieces of `data1` & `data2` together into `res`.
  ## Returns the new length, which is not greater than `maxOutLen`.
  ## Should produce the same mutation given the same `seed`.

proc mutate(data: var openarray[byte], maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerMutate".}
  ## Experimental, may go away in future.
  ## libFuzzer-provided procedure to be used inside `customMutator`.
  ## Mutates raw data in `data` inplace.
  ## Returns the new length, which is not greater than `maxLen`.
