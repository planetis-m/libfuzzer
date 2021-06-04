=========================================================
                        libFuzzer
=========================================================

Thin interface for libFuzzer, an in-process, coverage-guided, evolutionary fuzzing engine.

Read the `Documentation <https://planetis-m.github.io/libfuzzer/fuzztarget.html>`_

Example
=======

In 95% of cases all you need is to define the procedure ``testOneInput`` in your file.


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


Compile with: ``--cc:clang -t:"-fsanitize=fuzzer,address,undefined" -l:"-fsanitize=fuzzer,address,undefined" -d:nosignalhandler --nomain:on -g``

Structure-Aware Fuzzing
=======================

  But the lack of an input grammar can also result in inefficient fuzzing
  for complicated input types, where any traditional mutation (e.g. bit
  flipping) leads to an invalid input rejected by the target API in the
  early stage of parsing. With some additional effort, however, libFuzzer
  can be turned into a grammar-aware (i.e. structure-aware) fuzzing engine
  for a specific input type.

— [5]_

Take a look at the snappy compression `example <examples/compress/>`_.

Installation
============

- Copy the files ``libfuzzer/fuzztarget.{nim,nims}``, ``libfuzzer/standalone.nim`` at your testing directory.
- Fill in the implementations of the exported procedures.
- Compile and run with an empty corpus directory as an argument.

Presentations
=============

.. [#] Jonathan Metzman `Fuzzing 101 <https://www.youtube.com/watch?v=NI2w6eT8p-E>`_
.. [#] Justin Bogner `Adventures in Fuzzing Instruction Selection <https://www.youtube.com/watch?v=UBbQ_s6hNgg>`_
.. [#] Mateusz Jurczyk `Effective File Format Fuzzing <https://www.youtube.com/watch?v=qTTwqFRD1H8>`_

Further Readings
================

.. [#] `libFuzzer Tutorial <https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md>`_
.. [#] `Structure-Aware Fuzzing with libFuzzer <https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md>`_
.. [#] `Efficient Fuzzing Guide <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/testing/libfuzzer/efficient_fuzzing.md#efficient-fuzzing-guide>`_
