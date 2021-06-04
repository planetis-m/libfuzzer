import nake, std/strformat

task "docs", "Generate documentation":
  # https://nim-lang.github.io/Nim/docgen.html
  let
    name = "fuzztarget.nim"
    src = "libfuzzer/" / name
    dir = "docs/"
    doc = dir / name.changeFileExt(".html")
    url = "https://github.com/planetis-m/libfuzzer"
  if doc.needsRefresh(src):
    echo "Generating the docs..."
    direShell(nimExe, "doc --verbosity:0",
        &"--git.url:{url} --git.devel:master --git.commit:master --out:{dir} {src}")
  else:
    echo "Generating the docs skipped."
