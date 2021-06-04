import std/[os, strformat, strutils]

proc main* =
  ## Standalone main procedure for fuzz targets.
  ##
  ## Use `-d:fuzzSa` to include this file to provide reproducers for bugs
  ## when linking against libFuzzer is undesirable.
  stderr.write &"StandaloneFuzzTarget: running {paramCount()} inputs\n"
  discard initialize()
  for i in 1..paramCount():
    stderr.write &"Running: {paramStr(i)}\n"
    let buf = readFile(paramStr(i))
    discard testOneInput(toOpenArrayByte(buf, 0, buf.high))
    stderr.write &"Done:    {paramStr(i)}: ({formatSize(buf.len)})\n"

main()
