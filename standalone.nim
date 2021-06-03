# Standalone main procedure for fuzz targets.
#
# Include this file to provide reproducers for bugs when linking against libFuzzer
# or other fuzzing engine is undesirable.
import std/[os, strformat, strutils]

const inStadaloneTarget = true

# Forward declarations
proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".}
proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".}

proc main =
  stderr.write &"StandaloneFuzzTarget: running {paramCount()} inputs\n"
  discard initialize()
  for i in 1..paramCount():
    stderr.write &"Running: {paramStr(i)}\n"
    let buf = readFile(paramStr(i))
    discard testOneInput(toOpenArrayByte(buf, 0, buf.high))
    stderr.write &"Done:    {paramStr(i)}: ({formatSize(buf.len)})\n"
