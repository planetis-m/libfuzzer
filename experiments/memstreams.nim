import std/streams

type
  ReadStream* = ref ReadStreamObj
    ## A stream that encapsulates a openarray[byte].
  ReadStreamObj = object of StreamObj
    data: ptr UncheckedArray[byte]
    len, pos: int
  WriteStream* = ref WriteStreamObj
  WriteStreamObj = object of ReadStreamObj

proc `=sink`*(dest: var ReadStreamObj; source: ReadStreamObj) {.error.}
proc `=copy`*(dest: var ReadStreamObj; source: ReadStreamObj) {.error.}

proc `=sink`*(dest: var WriteStreamObj; source: WriteStreamObj) {.error.}
proc `=copy`*(dest: var WriteStreamObj; source: WriteStreamObj) {.error.}

proc rsAtEnd(s: Stream): bool =
  let s = ReadStream(s)
  result = s.pos >= s.len

proc rsSetPosition(s: Stream, pos: int) =
  let s = ReadStream(s)
  s.pos = clamp(pos, 0, s.len)

proc rsGetPosition(s: Stream): int =
  let s = ReadStream(s)
  result = s.pos

proc rsReadData(s: Stream, buffer: pointer, bufLen: int): int =
  let s = ReadStream(s)
  result = min(bufLen, s.len - s.pos)
  if result > 0:
    copyMem(buffer, addr s.data[s.pos], result)
    inc(s.pos, result)
  else:
    result = 0

proc rsPeekData(s: Stream, buffer: pointer, bufLen: int): int =
  let s = ReadStream(s)
  result = min(bufLen, s.len - s.pos)
  if result > 0:
    copyMem(buffer, addr s.data[s.pos], result)
  else:
    result = 0

proc wsWriteData(s: Stream, buffer: pointer, bufLen: int) =
  var s = WriteStream(s)
  if bufLen <= 0:
    return
  if s.pos + bufLen > s.len:
    raise newException(IOError, "cannot write to stream")
  copyMem(addr(s.data[s.pos]), buffer, bufLen)
  inc(s.pos, bufLen)

proc newReadStream*(s: openarray[byte]): ReadStream =
  result = ReadStream(
    data: cast[ptr UncheckedArray[byte]](s),
    len: s.len,
    pos: 0,
    closeImpl: nil,
    atEndImpl: rsAtEnd,
    setPositionImpl: rsSetPosition,
    getPositionImpl: rsGetPosition,
    readDataStrImpl: nil,
    readDataImpl: rsReadData,
    peekDataImpl: rsPeekData,
    writeDataImpl: nil
  )

proc newReadStream*(data: ptr UncheckedArray[byte], len: int): ReadStream =
  result = ReadStream(
    data: data,
    len: len,
    pos: 0,
    closeImpl: nil,
    atEndImpl: rsAtEnd,
    setPositionImpl: rsSetPosition,
    getPositionImpl: rsGetPosition,
    readDataStrImpl: nil,
    readDataImpl: rsReadData,
    peekDataImpl: rsPeekData,
    writeDataImpl: nil
  )

proc newWriteStream*(data: ptr UncheckedArray[byte], len: int): WriteStream =
  result = WriteStream(
    data: data,
    len: len,
    pos: 0,
    closeImpl: nil,
    atEndImpl: rsAtEnd,
    setPositionImpl: rsSetPosition,
    getPositionImpl: rsGetPosition,
    readDataStrImpl: nil,
    readDataImpl: nil,
    peekDataImpl: nil,
    writeDataImpl: wsWriteData
  )
