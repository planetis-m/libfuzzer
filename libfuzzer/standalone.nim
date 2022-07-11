import std/[os, strformat, strutils]

proc standaloneFuzzTarget* =
  ## Standalone main procedure for fuzz targets.
  ##
  ## Use `-d:fuzzSa` to call `standaloneFuzzTarget` to provide reproducers
  ## for bugs when linking against libFuzzer is undesirable.
  stderr.write &"StandaloneFuzzTarget: running {paramCount()} inputs\n"
  #discard initialize()
  for i in 1..paramCount():
    stderr.write &"Running: {paramStr(i)}\n"
    var buf = readFile(paramStr(i))
    discard testOneInput(cast[ptr UncheckedArray[byte]](cstring(buf)), buf.len)
    stderr.write &"Done:    {paramStr(i)}: ({formatSize(buf.len)})\n"

standaloneFuzzTarget()
