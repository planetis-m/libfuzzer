import std/[hashes, strformat]

const
  Separator = "-########-"
  Target = "A-########-B"

var
  sink: int
  printed: int

proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  result = 0
  const targetHash = hash(Target)
  var strHash = hash(data)
  # Ensure we have 'A' and 'B' in the corpus.
  if data.len == 1 and data[0] == byte'A':
    inc(sink)
  if data.len == 1 and data[0] == byte'B':
    dec(sink)
  if targetHash == strHash:
    quit "BINGO; Found the target, exiting"

proc customCrossOver(data1: openarray[byte], data2: openarray[byte],
    res: var openarray[byte], seed: int64): int {.
    exportc: "LLVMFuzzerCustomCrossOver".} =
  var separatorLen = len(Separator)
  if printed < 32:
    stderr.write &"In LLVMFuzzerCustomCrossover {data1.len} {data2.len}\n"
  inc(printed)
  result = data1.len + data2.len + separatorLen
  if result > res.len:
    return 0
  for i in 0..<data1.len: res[i] = data1[i]
  for i in 0..<separatorLen: res[i+data1.len] = Separator[i].byte
  for i in 0..<data2.len: res[i+data1.len+separatorLen] = data2[i]
