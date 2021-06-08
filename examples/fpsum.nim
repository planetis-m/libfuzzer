# https://rigtorp.se/fuzzing-floating-point-code/
import std/[random, fenv, math]

proc sum(x: openArray[float]): float =
  result = 0.0
  for b in items(x):
    result = if isNaN(b): result else: result + b

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  let cLen = len div sizeof(float)
  if cLen == 0: return
  var copy = newSeq[float](cLen)
  copyMem(addr copy[0], data, copy.len * sizeof(float))

  let res = sum(copy)
  if isNaN(res):
    quitOrDebug()

proc customMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator", raises: [].} =

  let cLen = len div sizeof(float)
  if cLen == 0:
    var tmp = @[1.0, 3, 3, 7] # Use a dummy value
    result = tmp.len * sizeof(float)
    copyMem(data, addr tmp[0], result)
    return
  var copy = newSeq[float](cLen)
  copyMem(addr copy[0], data, copy.len * sizeof(float))
  var gen = initRand(seed)

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

  result = copy.len * sizeof(float)
  if result <= maxLen:
    copyMem(data, addr copy[0], result)
  else:
    result = 0

proc customCrossOver(data1: ptr UncheckedArray[byte], len1: int,
    data2: ptr UncheckedArray[byte], len2: int, res: ptr UncheckedArray[byte],
    maxResLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomCrossOver", raises: [].} =

  let cLen1 = len1 div sizeof(float)
  if cLen1 == 0: return
  var copy1 = newSeq[float](cLen1)
  copyMem(addr copy1[0], data1, copy1.len * sizeof(float))

  let cLen2 = len2 div sizeof(float)
  if cLen2 == 0: return
  var copy2 = newSeq[float](cLen2)
  copyMem(addr copy2[0], data2, copy2.len * sizeof(float))

  let len = min(copy1.len, min(copy2.len, maxResLen div sizeof(float)))
  if len == 0: return
  var buf = newSeq[float](len)
  copyMem(addr buf[0], res, buf.len * sizeof(float))

  var gen = initRand(seed)
  for i in 0 ..< buf.len:
    buf[i] = if gen.rand(1.0) <= 0.5: copy1[i] else: copy2[i]

  result = buf.len * sizeof(float)
  assert result <= maxResLen
  copyMem(res, addr buf[0], result)
