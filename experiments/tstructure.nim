import std/streams, bingo, memstreams, chroma

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc fuzzTarget(color: ColorRgb) =
  let hsl = color.asHsl
  let rgb = hsl.asRgb
  # This should be true for all RGB -> HSL -> RGB conversions!
  doAssert color == rgb

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  var target: ColorRgb
  try:
    let str = newReadStream(data, len)
    loadBin(str, target)
  except:
    return
  fuzzTarget(target)
