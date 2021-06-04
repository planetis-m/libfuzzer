import snappy, std/strutils

proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  # Decompress the input data and crash if it starts with "boom".
  let data = cast[string](uncompress(data))
  if data.startsWith("boom"): quit(QuitFailure)

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} = discard

when defined(fuzzSa):
  include/standalone
else:
  proc mutate(data: ptr UncheckedArray[byte]; len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

  proc customMutator(data: ptr UncheckedArray[byte]; len, maxLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomMutator".} =
    # Decompress the input data. If that fails, use a dummy value.
    var uncompressed = uncompress(data.toOpenArray(0, len-1))
    if uncompressed.len == 0: uncompressed = cast[seq[byte]](@"hi")
    # Mutate the uncompressed data with `libFuzzer`'s default mutator. Expand
    # the `decompressed` seq's for inserting mutations via `grow`.
    let oldLen = uncompressed.len
    uncompressed.grow(oldLen*2, 0)
    let newDecompressedLen = mutate(cast[ptr UncheckedArray[byte]](addr uncompressed[0]),
        oldLen, uncompressed.len)
    # Recompress the mutated data.
    let compressed = compress(uncompressed.toOpenArray(0, newDecompressedLen-1))
    # Copy the recompressed mutated data into `data` and return the new length.
    result = min(maxLen, compressed.len)
    for i in 0..<result: data[i] = compressed[i]
