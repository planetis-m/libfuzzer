# Standalone main procedure for fuzz targets.
#
# Use this file to provide reproducers for bugs when linking against libFuzzer
# or other fuzzing engine is undesirable.
import std/[os, strformat, strutils]

proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} = discard "to implement"
proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} = discard "to implement"

proc main =
  stderr.write &"StandaloneFuzzTargetMain: running {paramCount()} inputs\n"
  discard initialize()
  for i in 1..paramCount():
    stderr.write &"Running: {paramStr(i)}\n"
    let buf = readFile(paramStr(i))
    discard testOneInput(toOpenArrayByte(buf, 0, buf.high))
    stderr.write &"Done:    {paramStr(i)}: ({formatSize(buf.len)})\n"
