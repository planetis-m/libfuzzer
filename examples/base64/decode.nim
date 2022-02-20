# todo try to reason if this is needed
import std/base64

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
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
    proc NimMain() {.importc: "NimMain".}
    NimMain()

  proc mutate(data: ptr UncheckedArray[byte]; len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

  proc customMutator(data: ptr UncheckedArray[byte]; len, maxLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomMutator", raises: [].} =
    # Decompress the input data. If that fails, use a dummy value.

    var copy = newString(len)
    copyMem(addr copy[0], data, len)
    var decoded = try: decode(copy) except: "hi"
    # Mutate the decoded data with `libFuzzer`'s default mutator. Expand
    # the `decompressed` seq's for inserting mutations via `grow`.
    let oldLen = decoded.len
    decoded.setLen(oldLen*2)
    let newDecodedLen = mutate(cast[ptr UncheckedArray[byte]](addr decoded[0]),
        oldLen, decoded.len)
    # Recompress the mutated data.
    var encoded = encode(decoded.toOpenArray(0, newDecodedLen-1))
    # Copy the recompressed mutated data into `data` and return the new length.
    result = min(maxLen, encoded.len)
    copyMem(addr data[0], addr encoded[0], result)
    #for i in 0..<result: data[i] = encoded[i].byte
