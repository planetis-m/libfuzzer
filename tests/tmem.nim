# Contrived example of ASan poisoning, use `-d:useMalloc`
# https://github.com/mcgov/asan_alignment_example
import std/strutils

proc poisonMem(region: pointer, size: int) {.header:
    "sanitizer/asan_interface.h", importc: "ASAN_POISON_MEMORY_REGION".}

proc unpoisonMem(region: pointer, size: int) {.header:
    "sanitizer/asan_interface.h", importc: "ASAN_UNPOISON_MEMORY_REGION".}

template `+!`(p: pointer, s: int): pointer =
  cast[pointer](cast[int](p) +% s)

type
  Point = object
    x: float32

var
  points = newSeq[Point](5)
# Print the address
echo cast[ByteAddress](addr points[1]).toHex
# Poison the entire seq
poisonMem(addr points[0], points.len * sizeof(Point))
# Create a Point
unpoisonMem(addr points[1], sizeof(Point))
points[1] = Point(x: 1)
echo points[1]
# Pretend to destroy `points[1]`
poisonMem(addr points[1], sizeof(Point))
echo points[1]
