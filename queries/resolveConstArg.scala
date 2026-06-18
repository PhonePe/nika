import io.shiftleft.codepropertygraph.generated.nodes.{Call, Literal, Identifier}

def loadParams(path: String): Map[String, Seq[String]] = {
    val decoder = java.util.Base64.getDecoder
    val source = scala.io.Source.fromFile(path)
    try {
        source.getLines().map(_.trim).filter(_.nonEmpty).toList.flatMap { line =>
            val tab = line.indexOf('\t')
            if (tab < 0) None
            else Some((line.substring(0, tab), new String(decoder.decode(line.substring(tab + 1)), "UTF-8")))
        }.groupBy(_._1).map { case (k, kvs) => (k, kvs.map(_._2)) }
    } finally source.close()
}

def resolveArgValues(fileName: String, lineNumber: Int): List[String] = {
    val regexFileName = ".*" + fileName
    val calls = cpg.file.name(regexFileName).method.call.filter(_.lineNumber.exists(_ == lineNumber)).l
    calls.flatMap { call =>
        call.argument.l.flatMap {
            case lit: Literal => List(lit.code)
            case id: Identifier =>
                val name = id.name
                call.method.ast.isCall.name("<operator>.assignment")
                    .filter(_.argument.argumentIndex(1).code.headOption.contains(name))
                    .flatMap(_.argument.argumentIndex(2).collectAll[Literal].code).l
            case _ => List.empty[String]
        }
    }.distinct
}

def resolveBatch(paramsPath: String, outputPath: String): Unit = {
    def esc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")
    val params = loadParams(paramsPath)
    val out = scala.collection.mutable.ArrayBuffer[String]()
    for (loc <- params.getOrElse("location", Seq.empty)) {
        val tab = loc.lastIndexOf('\t')
        if (tab > 0) {
            val fileName = loc.substring(0, tab)
            try {
                val ln = loc.substring(tab + 1).toInt
                val vals = resolveArgValues(fileName, ln)
                out += s"""{"file":"${esc(fileName)}","line":$ln,"values":[${vals.map(v => "\"" + esc(v) + "\"").mkString(",")}]}"""
            } catch { case _: Exception => }
        }
    }
    val w = new java.io.PrintWriter(new java.io.File(outputPath))
    try w.write(out.mkString("[", ",", "]")) finally w.close()
}
