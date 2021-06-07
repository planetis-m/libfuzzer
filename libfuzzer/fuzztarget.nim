## NOTE: the libFuzzer interface is thin and in the majority of cases
## all you need is to define the procedure `testOneInput` in your file.

proc testOneInput*(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  ## Mandatory user-provided target procedure.
  ## Executes the code under test with `data` as the input.
  ## libFuzzer will invoke this procedure *many* times with different inputs.
  ## Must return 0.
  discard "to implement"

proc initialize*(): cint {.exportc: "LLVMFuzzerInitialize".} =
  ## Optional user-provided initialization procedure.
  ## If provided, this procedure will be called by libFuzzer once at startup.
  ## Must return 0.
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".} # Keep this line
  discard "to implement"

when defined(fuzzSa) or defined(nimdoc):
  include standalone
when not defined(fuzzSa) or defined(nimdoc):
  proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}
    ## Experimental, may go away in future.
    ## libFuzzer-provided procedure to be used inside `customMutator`.
    ## Mutates raw data in `data[0..<len]` inplace.
    ## Returns the new length, which is not greater than `maxLen`.

  proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomMutator".} =
    ## Optional user-provided custom mutator.
    ## Mutates raw data in `data[0..<len]` inplace.
    ## Returns the new length, which is not greater than `maxLen`.
    ## Given the same `seed` produces the same mutation.
    discard "to implement"

  proc customCrossOver*(data1: ptr UncheckedArray[byte], len1: int,
      data2: ptr UncheckedArray[byte], len2: int, res: ptr UncheckedArray[byte],
      maxResLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomCrossOver".} =
    ## Optional user-provided custom cross-over procedure.
    ## Combines pieces of `data1` & `data2` together into `res`.
    ## Returns the new length, which is not greater than `maxResLen`.
    ## Should produce the same mutation given the same `seed`.
    discard "to implement"
