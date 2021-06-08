import std/[hashes, strformat]

const
  Separator = "-########-"
  Target = "A-########-B"

var
  sink: int
  printed: int

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput*(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  const targetHash = hash(Target)
  var strHash = hash(data.toOpenArray(0, len-1))
  # Ensure we have 'A' and 'B' in the corpus.
  if len == 1 and data[0] == byte'A':
    inc(sink)
  if len == 1 and data[0] == byte'B':
    dec(sink)
  if targetHash == strHash:
    quit "BINGO; Found the target, exiting"

proc customCrossOver(data1: ptr UncheckedArray[byte], len1: int,
    data2: ptr UncheckedArray[byte], len2: int, res: ptr UncheckedArray[byte],
    maxResLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomCrossOver", raises: [].} =
  const separatorLen = len(Separator)
  if printed < 32:
    try: stderr.write &"In customCrossover {len1} {len2}\n" except: discard
  inc(printed)
  result = len1 + len2 + separatorLen
  if result > maxResLen:
    return 0
  for i in 0..<len1: res[i] = data1[i]
  for i in 0..<separatorLen: res[i+len1] = Separator[i].byte
  for i in 0..<len2: res[i+len1+separatorLen] = data2[i]
