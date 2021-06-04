import nake, std/[os, strformat]

task "doc", "Generate documentation":
  let
    src = "fuzztarget.nim"
    dir = "docs/"
    doc = dir & src.changeFileExt(".html")
  if doc.needsRefresh(src):
    direShell(nimExe, &" doc --out:{dir} {src}")
  else:
    echo "All done!"
