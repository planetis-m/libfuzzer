# https://www.moritz.systems/blog/an-introduction-to-llvm-libfuzzer/
# Compile with and without asan builtin interceptors "-fsanitize=fuzzer(,address)"
# ./tstring -runs=1000000

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  if len >= 7:
    var copy = newString(6)
    copyMem(cstring(copy), cast[cstring](data), copy.len)
    if copy == "qwerty":
      stderr.write("BINGO\n")
      quitOrDebug()
