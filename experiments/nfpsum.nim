# https://rigtorp.se/fuzzing-floating-point-code/
import std/[random, fenv, math, streams], bingo, memstreams

proc sum(x: openArray[float]): float =
  result = 0.0
  for b in items(x):
    result = if isNaN(b): result else: result + b

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  var copy: seq[float]
  try:
    let str = newReadStream(data, len)
    loadBin(str, copy)
  except:
    return
  if copy.len == 0: return
  let res = sum(copy)
  if isNaN(res):
    quitOrDebug()

when defined(fuzzSa):
  include libfuzzer/standalone
else:
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

  proc customMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomMutator", raises: [].} =

    proc rfp(gen: var Rand): float =
      case gen.rand(10)
      of 0:
        result = NaN
      of 1:
        result = minimumPositiveValue(float)
      of 2:
        result = maximumPositiveValue(float)
      of 3:
        result = -minimumPositiveValue(float)
      of 4:
        result = -maximumPositiveValue(float)
      of 5:
        result = epsilon(float)
      of 6:
        result = -epsilon(float)
      of 7:
        result = Inf
      of 8:
        result = -Inf
      of 9:
        result = 0.0
      else:
        result = gen.rand(-1.0..1.0)

    var copy: seq[float]
    try:
      let readStr = newReadStream(data, len)
      loadBin(readStr, copy)
    except:
      var tmp = @[1.0, 3, 3, 7] # Use a dummy value
      let writeStr = newStringStream(newStringOfCap(tmp.len * sizeof(float)))
      try: writeStr.storeBin(tmp) except: discard
      result = writeStr.data.len
      assert result <= maxLen
      copyMem(data, addr writeStr.data[0], result)
      return

    if copy.len == 0: return
    var gen = initRand(seed)
    case gen.rand(3)
    of 0: # Change element
      if copy.len > 0:
        copy[gen.rand(0..<copy.len)] = rfp(gen)
    of 1: # Add element
      copy.add rfp(gen)
    of 2: # Delete element
      if copy.len > 0:
        discard copy.pop
    else: # Shuffle elements
      gen.shuffle(copy)

    let writeStr = newStringStream(newStringOfCap(copy.len * sizeof(float)))
    try: writeStr.storeBin(copy) except: discard
    result = writeStr.data.len
    if result <= maxLen:
      copyMem(data, addr writeStr.data[0], result)
    else:
      result = len

  proc customCrossOver(data1: ptr UncheckedArray[byte], len1: int,
      data2: ptr UncheckedArray[byte], len2: int, res: ptr UncheckedArray[byte],
      maxResLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomCrossOver", raises: [].} =

    var copy1: seq[float]
    try:
      let readStr1 = newReadStream(data1, len1)
      loadBin(readStr1, copy1)
    except:
      return

    var copy2: seq[float]
    try:
      let readStr2 = newReadStream(data2, len2)
      loadBin(readStr2, copy2)
    except:
      return

    let len = min(copy1.len, min(copy2.len, maxResLen div sizeof(float)))
    if len == 0: return
    var buf = newSeq[float](len)

    var gen = initRand(seed)
    for i in 0 ..< buf.len:
      buf[i] = if gen.rand(1.0) <= 0.5: copy1[i]
               else: copy2[i]

    let writeStr = newStringStream(newStringOfCap(buf.len * sizeof(float)))
    try: writeStr.storeBin(buf) except: discard
    result = writeStr.data.len
    if result <= maxResLen:
      copyMem(res, addr writeStr.data[0], result)
    else:
      result = 0
