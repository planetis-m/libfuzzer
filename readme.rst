=========================================================
                        libFuzzer
=========================================================

Thin interface for libFuzzer, an in-process, coverage-guided, evolutionary fuzzing engine.

Example
=======

.. code-block:: nim

  proc fuzzMe(data: openarray[byte]): bool =
    result = data.len >= 3 and
      data[0].char == 'F' and
      data[1].char == 'U' and
      data[2].char == 'Z' and
      data[3].char == 'Z' # :‑<

  proc testOneInput(data: openarray[byte]): cint {.exportc: "LLVMFuzzerTestOneInput".} =
    result = 0
    discard fuzzMe(data)


Installation
============


Presentations
=============

1. Jonathan Metzman [Fuzzing 101](https://www.youtube.com/watch?v=NI2w6eT8p-E)
1. Justin Bogner [Adventures in Fuzzing Instruction Selection](https://www.youtube.com/watch?v=UBbQ_s6hNgg)
1. Mateusz Jurczyk [Effective File Format Fuzzing](https://www.youtube.com/watch?v=qTTwqFRD1H8)

Further Readings
================

1. [libFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
1. [Structure-Aware Fuzzing with libFuzzer](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md)
1. [Efficient Fuzzing Guide](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/testing/libfuzzer/efficient_fuzzing.md#efficient-fuzzing-guide)
