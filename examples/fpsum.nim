# https://rigtorp.se/fuzzing-floating-point-code/
import std/[random, fenv, math]

proc sum(x: openArray[float]): float =
  result = 0.0
  for b in items(x):
    result = if isNaN(b): result else: result + b

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =

  let n = data.len div sizeof(float)
  let data = cast[ptr UncheckedArray[float]](data)

  let res = sum(toOpenArray(data, 0, n-1))
  if isNaN(res):
    quitOrDebug()
  result = 0

proc customMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =

  var n = len div sizeof(float)
  let data = cast[ptr UncheckedArray[float]](data)

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
    if n > 0:
      data[gen.rand(0..<n)] = rfp(gen)
  of 1: # Add element
    if n <= maxLen:
      data[n] = rfp(gen)
      inc n
  of 2: # Delete element
    if n > 0:
      dec n
  else: # Shuffle elements
    # toOpenArray, issue #15745
    for i in countdown(n-1, 1):
      let j = gen.rand(i)
      swap(data[i], data[j])
  result = n * sizeof(float)

proc customCrossOver(data1: openarray[byte], data2: openarray[byte],
    res: var openarray[byte], seed: int64): int {.
    exportc: "LLVMFuzzerCustomCrossOver".} =

  let n = min(data1.len, min(data2.len, res.len)) div sizeof(float)
  let data1 = cast[ptr UncheckedArray[float]](data1)
  let data2 = cast[ptr UncheckedArray[float]](data2)
  let res = cast[ptr UncheckedArray[float]](res)

  var gen = initRand(seed)
  for i in 0 ..< n:
    res[i] = if gen.rand(1.0) <= 0.5: data1[i] else: data2[i]
  result = n * sizeof(float)
