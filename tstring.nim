import strutils

proc testOneInput*(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  if data.len >= 7:
    var copy = newString(6)
    copyMem(cstring(copy), data, copy.len)
    if rfind(copy, "qwertyuiopasdfghjklzxcvbnm") == 0:
      stderr.write("BINGO\n")
      quit(1)
