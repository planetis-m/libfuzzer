# Alternative to strict .raises: []
proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

template testOneInput*(body: untyped) =
  proc LLVMFuzzerTestOneInput(data {.inject.}: ptr UncheckedArray[byte],
      len {.inject.}: int): cint {.exportc.} =
    try:
      body
    finally: {.emit: "nimTestErrorFlag();".}

template customMutator*(body: untyped) =
  proc LLVMFuzzerCustomMutator(data {.inject.}: ptr UncheckedArray[byte];
      len {.inject.}, maxLen {.inject.}: int, seed {.inject.}: int64): int {.exportc.} =
    try:
      body
    finally: {.emit: "nimTestErrorFlag();".}

template customCrossOver*(body: untyped) =
  proc LLVMFuzzerCustomCrossOver*(data1 {.inject.}: ptr UncheckedArray[byte], len1 {.inject.}: int,
      data2 {.inject.}: ptr UncheckedArray[byte], len2 {.inject.}: int,
      res {.inject.}: ptr UncheckedArray[byte], maxResLen {.inject.}: int,
      seed {.inject.}: int64): int {.exportc.} =
    try:
      body
    finally: {.emit: "nimTestErrorFlag();".}

testOneInput:
  if true:
    raise newException(ValueError, "my my my")
