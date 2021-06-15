import std/strformat

{.pragma: noASan, codegenDecl: "__attribute__((no_sanitize_address)) $# $#$#".}

proc getShadowMapping(shadowScale, shadowOffset: ptr int) {.header:
    "sanitizer/asan_interface.h", importc: "__asan_get_shadow_mapping".}

var
  shadowMemoryScale: int
  shadowMemoryOffset: int

getShadowMapping(addr shadowMemoryScale, addr shadowMemoryOffset)

proc printShadowMemoryImpl(address: pointer, filename: string, line: int) {.noASan.} =
  let shadowMemory = cast[ptr UncheckedArray[uint8]](
      cast[uint](address) shr shadowMemoryScale + shadowMemoryOffset.uint)
  stdout.write(&"Shadow Memory at {filename}:{line}\n")
  stdout.write(&"{cast[ByteAddress](address):#x}: {shadowMemory[0]:02x} {shadowMemory[1]:02x} {shadowMemory[2]:02x} {shadowMemory[3]:02x} {shadowMemory[4]:02x} {shadowMemory[5]:02x} {shadowMemory[6]:02x} {shadowMemory[7]:02x}\n")

template printShadowMemory*(address: untyped) =
  let (filename, line, _) = instantiationInfo()
  printShadowMemoryImpl(address, filename, line)
