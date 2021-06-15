import std/strformat

{.pragma: noASan, codegenDecl: "$# __declspec(no_sanitize_address) $#$#".}

proc getShadowMapping(shadowScale, shadowOffset: ptr int) {.header:
    "sanitizer/asan_interface.h", importc: "__asan_get_shadow_mapping".}

var
  shadowMemoryScale*: int
  shadowMemoryOffset*: int

getShadowMapping(addr shadowMemoryScale, addr shadowMemoryOffset)

proc printShadowMemory*(address: pointer) {.noASan.} =
  let shadowMemory = cast[ptr UncheckedArray[uint8]](
      cast[uint](address) shr shadowMemoryScale + shadowMemoryOffset.uint)
  let (filename, line, _) = instantiationInfo()
  stdout.write(&"Shadow Memory at {filename}:{line}\n")
  stdout.write(&"{cast[ByteAddress](address):#x}: {shadowMemory[0]:02x} {shadowMemory[1]:02x} {shadowMemory[2]:02x} {shadowMemory[3]:02x} {shadowMemory[4]:02x} {shadowMemory[5]:02x} {shadowMemory[6]:02x} {shadowMemory[7]:02x}\n")
