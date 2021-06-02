import snappy, std/strutils

proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  # Decompress the input data and crash if it starts with "boom".
  let data = cast[string](uncompress(data))
  doAssert not data.startsWith("boom") # raises an assertion & unwinds the stack

proc mutate(data: var openarray[byte], maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

proc customMutator(data: var openarray[byte], maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  # Decompress the input data. If that fails, use a dummy value.
  var uncompressed = uncompress(data)
  if uncompressed.len == 0: uncompressed = cast[seq[byte]](@"hi")
  # Mutate the uncompressed data with `libFuzzer`'s default mutator. Expand
  # the `decompressed` seq's for inserting mutations via `grow`.
  let oldLen = uncompressed.len
  uncompressed.grow(oldLen*2, 0)
  let newDecompressedLen = mutate(uncompressed.toOpenArray(0, oldLen-1), uncompressed.len)
  # Recompress the mutated data.
  let compressed = compress(uncompressed.toOpenArray(0, newDecompressedLen-1))
  # Copy the recompressed mutated data into `data` and return the new length.
  result = min(maxLen, compressed.len)
  for i in 0..<result: data[i] = compressed[i]
