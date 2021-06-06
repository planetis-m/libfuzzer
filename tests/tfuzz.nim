# https://llvm.org/docs/LibFuzzer.html

# --panics:on --gc:arc -d:useMalloc --cc:clang -t:"-fsanitize=fuzzer,address,undefined"
# -l:"-fsanitize=fuzzer,address,undefined" -d:nosignalhandler --nomain:on -d:danger -g

proc fuzzMe(data: openarray[byte]): bool =
  result = data.len >= 3 and
    data[0].char == 'F' and
    data[1].char == 'U' and
    data[2].char == 'Z' and
    data[3].char == 'Z' # :‑<

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  result = 0
  discard fuzzMe(data.toOpenArray(0, len-1))
