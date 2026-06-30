import scala.collection.mutable
import io.shiftleft.codepropertygraph.generated.nodes.Method
import java.util.regex.Pattern

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

def esc(s: String): String = {
    val sb = new StringBuilder
    s.foreach {
        case '\\' => sb.append("\\\\")
        case '"'  => sb.append("\\\"")
        case '\n' => sb.append("\\n")
        case '\r' => sb.append("\\r")
        case '\t' => sb.append("\\t")
        case '\b' => sb.append("\\b")
        case '\f' => sb.append("\\f")
        case c if c < 0x20 => sb.append("\\u%04x".format(c.toInt))
        case c => sb.append(c)
    }
    sb.toString
}

def getMethodDefinition(m: Method): String = {
    def extractByLines(content: String, start: Int, end: Int): String =
        content.split("\\r?\\n").slice(start - 1, end).mkString("\n")

    def extractByStartLine(content: String, start: Int): String = {
        val lines = content.split("\\r?\\n", -1)
        if (start < 1 || start > lines.length) return ""

        val sb = new StringBuilder
        var idx = start - 1
        var started = false
        var depth = 0
        var seenOpeningBrace = false

        while (idx < lines.length) {
            val line = lines(idx)
            if (started) sb.append("\n")
            sb.append(line)
            started = true

            var i = 0
            while (i < line.length) {
                val ch = line.charAt(i)
                if (ch == '{') {
                    depth += 1
                    seenOpeningBrace = true
                } else if (ch == '}') {
                    if (depth > 0) depth -= 1
                }
                i += 1
            }

            if (seenOpeningBrace && depth == 0) {
                return sb.toString
            }

            idx += 1
        }

        sb.toString
    }

    def readFromFs(path: String): Option[String] = {
        if (path == null || path.isEmpty) return None
        try {
            val file = new java.io.File(path)
            if (file.exists() && file.isFile) {
                Some(scala.io.Source.fromFile(file, "UTF-8").mkString)
            } else {
                val rootPath = cpg.metaData.root.headOption.getOrElse("")
                if (rootPath.nonEmpty) {
                    val rooted = new java.io.File(rootPath, path)
                    if (rooted.exists() && rooted.isFile) {
                        Some(scala.io.Source.fromFile(rooted, "UTF-8").mkString)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        } catch {
            case _: Exception => None
        }
    }

    val fallbackAst = {
        val blockCode = Option(m.block).map(_.code).getOrElse("")
        if (blockCode.trim.nonEmpty) {
            val signature = if (m.code != null && m.code.trim.nonEmpty) m.code else s"${m.name}(...)"
            s"${signature}\n${blockCode}"
        } else if (m.code != null) {
            m.code
        } else {
            ""
        }
    }

    try {
        val lineStartOpt = m.lineNumber.map(_.toInt)
        val lineEndOpt = m.lineNumberEnd.map(_.toInt)
        val blockStartOpt = Option(m.block).flatMap(_.lineNumber).map(_.toInt)

        def fromContent(content: String): String = {
            val fullStartOpt = lineStartOpt.orElse(blockStartOpt)
            val fullEndOpt = lineEndOpt

            val byRange = (fullStartOpt, fullEndOpt) match {
                case (Some(start), Some(end)) if end >= start => extractByLines(content, start, end)
                case _ => ""
            }

            if (byRange.trim.nonEmpty && byRange.split("\\r?\\n", -1).length > 1) byRange
            else {
                fullStartOpt.map(start => extractByStartLine(content, start)).getOrElse("")
            }
        }

        (m.lineNumber, m.lineNumberEnd) match {
            case (Some(_), _) =>
                val regexName = s".*${Pattern.quote(m.filename)}$$"
                val baseName = new java.io.File(m.filename).getName
                val regexBase = s".*/${Pattern.quote(baseName)}$$"
                val fromCpg = cpg.file.nameExact(m.filename).headOption.map(_.content)
                    .orElse(cpg.file.name(regexName).headOption.map(_.content))
                    .orElse(cpg.file.name(regexBase).headOption.map(_.content))
                    .map(fromContent)
                    .getOrElse("")

                if (fromCpg.trim.nonEmpty) fromCpg
                else {
                    val fromFs = readFromFs(m.filename)
                        .map(fromContent)
                        .getOrElse("")
                    if (fromFs.trim.nonEmpty) fromFs
                    else fallbackAst
                }
            case _ =>
                fallbackAst
        }
    } catch {
        case _: Exception => fallbackAst
    }
}

// Aggressive reachability: call-graph-only (no taint tracking)

def findAggressivePathsBatch(paramsPath: String, outputPath: String, sanitizers: Seq[String] = Seq.empty): Unit = {
    val lines = loadParams(paramsPath).getOrElse("pair", Seq.empty).toArray
    println(s"[aggressive-batch] Processing ${lines.length} pairs")

    val sanitizerSet = sanitizers.toSet
    def chainSanitized(chain: Seq[Method]): Boolean =
        sanitizers.nonEmpty && chain.exists(m =>
            sanitizerSet.contains(m.name) || sanitizers.exists(s => m.fullName.contains(s)))

    val sourceCache = mutable.Map[String, Option[Method]]()
    val allResults = mutable.ArrayBuffer[String]()
    var processed = 0
    var skippedNoData = 0

    for (line <- lines) {
        val parts = line.split("\t")
        if (parts.length >= 3) {
            val sourceFullName = parts(0)
            val lineNumber = parts(1).toInt
            val fileName = parts(2)
            val regexFileName = ".*" + Pattern.quote(fileName) + "$"

            processed += 1
            if (processed % 100 == 0) {
                println(s"[aggressive-batch] Progress: $processed / ${lines.length}")
            }

            try {
                val sourceOpt = sourceCache.getOrElseUpdate(sourceFullName,
                    cpg.method.fullNameExact(sourceFullName).headOption
                )

                if (sourceOpt.isEmpty) {
                    skippedNoData += 1
                } else {
                    val sinkMethods = cpg.file.name(regexFileName).method.call.lineNumber(lineNumber).method.l

                    if (sinkMethods.isEmpty) {
                        skippedNoData += 1
                    } else {
                        // Fresh traversals for reachableByCallGraphWithChain
                        val sourceTrav = cpg.method.fullNameExact(sourceFullName)
                        val sinkTrav = cpg.file.name(regexFileName).method.call.lineNumber(lineNumber).method

                        val chains = sinkTrav.reachableByCallGraphWithChain(sourceTrav)

                        for (chain <- chains if chain.nonEmpty && !chainSanitized(chain)) {
                            val pathEntries = mutable.ArrayBuffer[String]()

                            chain.zipWithIndex.foreach { case (m, idx) =>
                                val methodDefinition = getMethodDefinition(m)
                                val (calleeCode, calleeLineNum) = if (idx < chain.size - 1) {
                                    val next = chain(idx + 1)
                                    val callsToNext = m.call.filter(_.methodFullName == next.fullName).l
                                    val resolvedCalls = if (callsToNext.nonEmpty) callsToNext else m.call.filter(_.name == next.name).l
                                    if (resolvedCalls.nonEmpty) {
                                        val bestCall = resolvedCalls.head
                                        (bestCall.code, bestCall.lineNumber.getOrElse(m.lineNumber.getOrElse("")).toString)
                                    } else ("", m.lineNumber.getOrElse("").toString)
                                } else {
                                    val sinkCallOpt = m.call.lineNumber(lineNumber).headOption
                                    (sinkCallOpt.map(_.code).getOrElse(""), lineNumber.toString)
                                }

                                val jsonObj = s"""{"methodname":"${esc(m.name)}","filename":"${esc(m.filename)}","isExternal":"${m.isExternal}","methodLineNumberStart":"${m.lineNumber.getOrElse("")}","methodLineNumberEnd":"${m.lineNumberEnd.getOrElse("")}","code":"${esc(methodDefinition)}","calleeCode":"${esc(calleeCode)}","calleeLineNumber":"${calleeLineNum}"}"""
                                pathEntries.append(jsonObj)
                            }

                            if (pathEntries.nonEmpty) {
                                val pathJson = pathEntries.mkString("[", ",", "]")
                                val entryJson = s"""{"source":"${esc(sourceFullName)}","lineNumber":$lineNumber,"fileName":"${esc(fileName)}","path":$pathJson}"""
                                allResults.append(entryJson)
                            }
                        }
                    }
                }
            } catch {
                case e: Exception =>
                    println(s"[aggressive-batch] Error processing pair $sourceFullName -> $fileName:$lineNumber : ${e.getMessage}")
            }
        }
    }

    println(s"[aggressive-batch] Done. Processed: $processed, Results: ${allResults.length}, Skipped no-data: $skippedNoData")

    val outputJson = allResults.mkString("[", ",", "]")
    val writer = new java.io.PrintWriter(new java.io.File(outputPath))
    try { writer.write(outputJson) } finally { writer.close() }
}
