import std/base64

proc testOneInput(data: ptr UncheckedArray[char], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  if len == 0: return
  var
    copy = newString(len)
    decoded: string
  copyMem(addr copy[0], data, len)
  try: decoded = decode(copy) except: return

when defined(fuzzSa):
  include libfuzzer/standalone
else:
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

  proc mutate(data: ptr UncheckedArray[char]; len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

  proc customMutator(data: ptr UncheckedArray[char]; len, maxLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomMutator", raises: [].} =
    # Decompress the input data. If that fails, use a dummy value.

    var copy = newString(len)
    copyMem(addr copy[0], data, len)
    var decoded = try: decode(copy) except: "hi"
    prepareMutation(decoded)
    # Mutate the decoded data with `libFuzzer`'s default mutator. Expand
    # the `decompressed` seq's for inserting mutations via `grow`.
    let oldLen = decoded.len
    decoded.setLen(oldLen*2)
    let newDecodedLen = mutate(cast[ptr UncheckedArray[char]](addr decoded[0]),
        oldLen, decoded.len)
    # Recompress the mutated data.
    let encoded = encode(decoded.toOpenArray(0, newDecodedLen-1))
    # Copy the recompressed mutated data into `data` and return the new length.
    result = min(maxLen, encoded.len)
    for i in 0..<result: data[i] = encoded[i]
