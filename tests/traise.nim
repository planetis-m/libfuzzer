
proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  if true:
    raise newException(ValueError, "")

proc customMutator(data: ptr UncheckedArray[byte]; len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  try:
    discard
  except:
    quitOrDebug()
