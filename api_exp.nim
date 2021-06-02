proc LLVMFuzzerMutate(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc.}
proc mutate(data: var openarray[byte], oldLen: int): int {.inline.} =
  LLVMFuzzerMutate(cast[ptr UncheckedArray[byte]](data), oldLen, data.len)
proc customMutator(data: var openarray[byte], oldLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} = discard "to implement"
proc LLVMFuzzerCustomMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc.} = customMutator(toOpenArray(data, 0, maxLen-1), len)
#Error: type mismatch: got <openArray[byte], int>
#but expected one of:
#proc customMutator(data: var openArray[byte]; oldLen: int; seed: int64): int
  #first type mismatch at position: 1
  #required type for data: var openArray[byte]
  #but expression 'toOpenArray(data, 0, maxLen - 1)' is immutable, not 'var'

#expression: customMutator(toOpenArray(data, 0, maxLen - 1), len)
