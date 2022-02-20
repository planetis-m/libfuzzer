import nake, std/strformat

const
  ProjectUrl = "https://github.com/planetis-m/libfuzzer"
  SourceDir = currentSourcePath().parentDir.quoteShell
  DocsDir = SourceDir / "docs"

task "docs", "Generate documentation":
  # https://nim-lang.github.io/Nim/docgen.html
  let
    name = "fuzztarget.nim"
    src = SourceDir / "libfuzzer" / name
    doc = DocsDir / name.changeFileExt(".html")
  if doc.needsRefresh(src):
    echo "Generating the docs..."
    direShell("nim doc",
        &"--verbosity:0 --git.url:{ProjectUrl} --git.devel:master --git.commit:master --out:{DocsDir} {src}")
  else:
    echo "Skipped generating the docs."
