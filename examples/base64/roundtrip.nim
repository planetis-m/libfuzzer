import std/base64

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  if len == 0: return
  let encoded = encode(data.toOpenArray(0, len-1))
  var decoded: string
  try: decoded = decode(encoded) except: return
  doAssert data.toOpenArray(0, len-1) == decoded

when defined(fuzzSa):
  include libfuzzer/standalone
else:
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}
