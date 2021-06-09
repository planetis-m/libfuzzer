# Alternative to strict .raises: []
proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

template trap(body: untyped) =
  try:
    body
  finally: {.emit: "nimTestErrorFlag();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", trap.} =
  if true:
    raise newException(ValueError, "my my my")
