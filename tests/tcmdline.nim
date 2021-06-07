# os.paramCount/paramStr not supported
import std/parseopt

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

var
  cmdCountPtr: ptr cint
  cmdLinePtr: ptr cstringArray

proc initialize(argc: ptr cint; argv: ptr cstringArray): cint {.exportc: "LLVMFuzzerInitialize".} =
  cmdCountPtr = argc
  cmdLinePtr = argv
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  let cmdline = cstringArrayToSeq(cmdLinePtr[], cmdCountPtr[])
  var p = initOptParser(cmdline)
  for kind, key, val in p.getopt():
    case kind
    of cmdLongOption, cmdShortOption:
      case key
      of "abort", "a": quitOrDebug()
    else: discard
