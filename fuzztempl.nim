# defined in llvm/projects/compiler-rt/lib/fuzzer/FuzzerInterface.h
# NOTE: the libFuzzer interface is thin and in the majority of cases
# you should not include this file into your target. In 95% of cases
# all you need is to define the procedure `testOneInput` in your file.

proc initialize: cint {.exportc: "LLVMFuzzerInitialize".} = discard "to implement"
  # Optional user-provided initialization procedure.
  # If provided, this procedure will be called by libFuzzer once at startup.
  # It may read and modify argc/argv.
  # Must return 0.

proc testOneInput(data: ptr UncheckedArray[byte], len: csizeT): cint {.
    exportc: "LLVMFuzzerTestOneInput".} = discard "to implement"
  # Mandatory user-provided target procedure.
  # Executes the code under test with [data, data+len) as the input.
  # libFuzzer will invoke this procedure *many* times with different inputs.
  # Must return 0.

proc customMutator(data: ptr UncheckedArray[byte], len, maxLen: csizeT, seed: cuint): cint {.
    exportc: "LLVMFuzzerCustomMutator".} = discard "to implement"
  # Optional user-provided custom mutator.
  # Mutates raw data in `[data, data+len)` inplace.
  # Returns the new length, which is not greater than `maxLen`.
  # Given the same `seed` produces the same mutation.

proc customCrossOver(data1: ptr UncheckedArray[byte], len1: csizeT,
    data2: ptr UncheckedArray[byte], len2: csizeT, res: ptr UncheckedArray[byte],
    maxOutLen: sizeT, seed: cuint): csizeT {.
    exportc: "LLVMFuzzerCustomCrossOver".} = discard "to implement"
  # Optional user-provided custom cross-over procedure.
  # Combines pieces of Data1 & Data2 together into Out.
  # Returns the new size, which is not greater than MaxOutSize.
  # Should produce the same mutation given the same Seed.

proc mutate(data: ptr UncheckedArray[byte], len, maxLen: csizeT, seed: cuint): csizeT {.
    exportc: "LLVMFuzzerMutate".}
  # Experimental, may go away in future.
  # libFuzzer-provided procedure to be used inside `customMutator`.
  # Mutates raw data in `[data, data+len)` inplace.
  # Returns the new length, which is not greater than `maxLen`.
