# Compare asm with C program for interceptors

proc testOneInput*(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  if data.len >= 7:
    var copy = newString(6)
    copyMem(cstring(copy), cast[cstring](data), copy.len)
    if copy == "qwerty":
      stderr.write("BINGO\n")
      quit(1)

proc strcmp(a, b: cstring): cint {.noSideEffect,
    importc, header: "<string.h>".}

#proc testOneInput*(data: openarray[byte]): cint {.
    #exportc: "LLVMFuzzerTestOneInput".} =
  #if data.len >= 7:
    #var copy = newString(6)
    #copyMem(cstring(copy), cast[cstring](data), copy.len)
    #if strcmp(cstring(copy), cstring"qwerty") == 0:
      #stderr.write("BINGO\n")
      #quit(1)
