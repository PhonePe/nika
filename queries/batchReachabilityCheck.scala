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
                Some(scala.io.Source.fromFile(file)(scala.io.Codec.UTF8).mkString)
            } else {
                val rootPath = cpg.metaData.root.headOption.getOrElse("")
                if (rootPath.nonEmpty) {
                    val rooted = new java.io.File(rootPath, path)
                    if (rooted.exists() && rooted.isFile) {
                        Some(scala.io.Source.fromFile(rooted)(scala.io.Codec.UTF8).mkString)
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

def findPathsBatch(
    paramsPath: String,
    outputPath: String,
    sanitizers: Seq[String] = Seq.empty,
    excludeArgAnnotations: Seq[String] = Seq.empty,
    excludeArgTypes: Seq[String] = Seq.empty
): Unit = {
    val lines = loadParams(paramsPath).getOrElse("pair", Seq.empty).toArray
    println(s"[batch] Processing ${lines.length} pairs" + (if (sanitizers.nonEmpty) s" (sanitizers: ${sanitizers.mkString(",")})" else ""))

    val sanitizerSet = sanitizers.toSet
    def isSanitizerCall(c: Call): Boolean =
        sanitizerSet.contains(c.name) || sanitizers.exists(s => c.methodFullName.contains(s))

    val excludeAnnoSet = excludeArgAnnotations
        .map(a => if (a.startsWith("@")) a.substring(1) else a)
        .filter(_.nonEmpty)
        .toSet
    val excludeTypeSet = excludeArgTypes.filter(_.nonEmpty).toSet

    case class PairSpec(
        sourceFullName: String,
        lineNumber: Int,
        fileName: String,
        matchStartLine: Option[Int],
        matchStartCol: Option[Int],
        matchEndLine: Option[Int],
        matchEndCol: Option[Int],
        operandCode: String,
        operandStartLine: Option[Int],
        operandStartCol: Option[Int],
        operandEndLine: Option[Int],
        operandEndCol: Option[Int],
        ruleId: String,
        sourceParameterIndexes: Set[Int],
        sinkId: String
    )

    def optionalInt(value: String): Option[Int] =
        if (value == null || value.trim.isEmpty) None
        else scala.util.Try(value.trim.toInt).toOption

    def decodeField(value: String): String = {
        if (value == null || value.isEmpty) ""
        else new String(java.util.Base64.getDecoder.decode(value), "UTF-8")
    }

    def parsePair(line: String): Option[PairSpec] = {
        val parts = line.split("\\t", -1)
        if (parts.length < 3) None
        else {
            optionalInt(parts(1)).map { sinkLine =>
                PairSpec(
                    parts(0),
                    sinkLine,
                    parts(2),
                    if (parts.length > 3) optionalInt(parts(3)) else None,
                    if (parts.length > 4) optionalInt(parts(4)) else None,
                    if (parts.length > 5) optionalInt(parts(5)) else None,
                    if (parts.length > 6) optionalInt(parts(6)) else None,
                    if (parts.length > 7) decodeField(parts(7)) else "",
                    if (parts.length > 8) optionalInt(parts(8)) else None,
                    if (parts.length > 9) optionalInt(parts(9)) else None,
                    if (parts.length > 10) optionalInt(parts(10)) else None,
                    if (parts.length > 11) optionalInt(parts(11)) else None,
                    if (parts.length > 12) decodeField(parts(12)) else "",
                    if (parts.length > 13) parts(13).split(",").flatMap(optionalInt).toSet else Set.empty,
                    if (parts.length > 14) decodeField(parts(14)) else ""
                )
            }
        }
    }

    def normalizePath(value: String): String =
        Option(value).getOrElse("").replace('\\', '/').stripPrefix("./")

    def sameFile(actual: String, expected: String): Boolean = {
        val normalizedActual = normalizePath(actual)
        val normalizedExpected = normalizePath(expected)
        normalizedActual == normalizedExpected ||
            normalizedActual.endsWith("/" + normalizedExpected)
    }

    def overlaps(
        nodeStartLine: Option[Int], nodeStartCol: Option[Int],
        nodeEndLine: Option[Int], nodeEndCol: Option[Int],
        rangeStartLine: Option[Int], rangeStartCol: Option[Int],
        rangeEndLine: Option[Int], rangeEndCol: Option[Int]
    ): Boolean = {
        if (rangeStartLine.isEmpty) true
        else if (nodeStartLine.isEmpty) false
        else {
            val nsLine = nodeStartLine.get
            val neLine = nodeEndLine.getOrElse(nsLine)
            val rsLine = rangeStartLine.get
            val reLine = rangeEndLine.getOrElse(rsLine)
            val lineOverlap = nsLine <= reLine && neLine >= rsLine
            if (!lineOverlap) false
            else if (nsLine == neLine && rsLine == reLine) {
                val nsCol = nodeStartCol.getOrElse(0)
                val neCol = nodeEndCol.getOrElse(Int.MaxValue)
                val rsCol = rangeStartCol.getOrElse(0)
                val reCol = rangeEndCol.getOrElse(Int.MaxValue)
                nsCol <= reCol && neCol >= rsCol
            } else true
        }
    }

    def inferredEndPosition(
        startLine: Option[Int],
        startCol: Option[Int],
        code: String
    ): (Option[Int], Option[Int]) = {
        if (startLine.isEmpty) (None, None)
        else {
            val lines = Option(code).getOrElse("").split("\\r?\\n", -1)
            val endLine = Some(startLine.get + lines.length - 1)
            val endCol = if (lines.length == 1) {
                startCol.map(_ + lines.head.length)
            } else {
                Some(lines.last.length + 1)
            }
            (endLine, endCol)
        }
    }

    def isExcludedParam(p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn): Boolean = {
        val annoExcluded =
            excludeAnnoSet.nonEmpty && p.annotation.name.exists(excludeAnnoSet.contains)
        val tfn = p.typeFullName
        val typeExcluded =
            excludeTypeSet.nonEmpty && tfn != null && tfn.nonEmpty &&
                (excludeTypeSet.contains(tfn) || excludeTypeSet.exists(t => tfn.endsWith("." + t)))
        annoExcluded || typeExcluded
    }

    val taintParamCache = mutable.Map[Long, List[io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn]]()
    def taintParams(source: Method, selectedIndexes: Set[Int]): List[io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn] = {
        val eligible = taintParamCache.getOrElseUpdate(source.id, {
            if (excludeAnnoSet.isEmpty && excludeTypeSet.isEmpty) source.parameter.l
            else source.parameter.filterNot(isExcludedParam).l
        })
        if (selectedIndexes.nonEmpty) eligible.filter(p => selectedIndexes.contains(p.index))
        else eligible
    }

    // ── Caches ──
    // source fullName → Method
    val sourceCache = mutable.Map[String, Option[Method]]()
    // (fileName, lineNumber) → list of candidate Call nodes
    val sinkCallCache = mutable.Map[(String, Int), List[Call]]()
    // method id → list of non-external callee Methods
    val calleeCache = mutable.Map[Long, List[Method]]()
    // source fullName → set of reachable method ids via BFS
    val bfsReachCache = mutable.Map[String, Set[Long]]()

    def getCallees(m: Method): List[Method] = {
        calleeCache.getOrElseUpdate(m.id, m.callee.filterNot(_.isExternal).l)
    }

    // BFS from source, return set of all reachable method ids
    def bfsReachableSet(source: Method): Set[Long] = {
        bfsReachCache.getOrElseUpdate(source.fullName, {
            val visited = mutable.Set[Long](source.id)
            val queue = mutable.Queue[Method](source)
            while (queue.nonEmpty) {
                val current = queue.dequeue()
                for (callee <- getCallees(current) if !visited.contains(callee.id)) {
                    visited += callee.id
                    queue.enqueue(callee)
                }
            }
            visited.toSet
        })
    }

    val allResults = mutable.ArrayBuffer[String]()
    var processed = 0
    var skippedBfs = 0
    var skippedNoData = 0

    for (line <- lines) {
        parsePair(line).foreach { pair =>
            val sourceFullName = pair.sourceFullName
            val lineNumber = pair.lineNumber
            val fileName = pair.fileName

            processed += 1
            if (processed % 100 == 0) {
                println(s"[batch] Progress: $processed / ${lines.length} (skipped BFS: $skippedBfs, skipped no-data: $skippedNoData)")
            }

            try {
                // Lookup source (cached)
                val sourceOpt = sourceCache.getOrElseUpdate(sourceFullName,
                    cpg.method.fullNameExact(sourceFullName).headOption
                )
                if (sourceOpt.isEmpty) {
                    skippedNoData += 1
                } else {
                    val source = sourceOpt.get

                    // Lookup sink call candidates (cached by file+line)
                    val callsOnSinkLine = sinkCallCache.getOrElseUpdate((fileName, lineNumber),
                        cpg.file.filter(f => sameFile(f.name, fileName)).method.call
                            .filter(c => c.lineNumber.exists(_ == lineNumber)).l
                    )
                    val callNodeCandidates = callsOnSinkLine.filter { c =>
                        val (endLine, endCol) = inferredEndPosition(
                            c.lineNumber, c.columnNumber, c.code
                        )
                        overlaps(
                            c.lineNumber, c.columnNumber, endLine, endCol,
                            pair.matchStartLine.orElse(Some(lineNumber)), pair.matchStartCol,
                            pair.matchEndLine, pair.matchEndCol
                        )
                    }

                    if (callNodeCandidates.isEmpty) {
                        skippedNoData += 1
                    } else {
                        // Find which candidate's method is the sink
                        var sinkFullName: Option[String] = None
                        var callNode: Option[Call] = None
                        var sinkCallNodeCount: Int = 0

                        // BFS pre-filter: check if ANY candidate sink method is reachable
                        val reachSet = bfsReachableSet(source)
                        val reachableCandidates = callNodeCandidates.filter { cand =>
                            val sinkMethodOpt = cpg.method.fullNameExact(cand.method.fullName).headOption
                            sinkMethodOpt.exists(sm => reachSet.contains(sm.id))
                        }

                        if (reachableCandidates.isEmpty) {
                            skippedBfs += 1
                        } else {
                            // Data flow check only on BFS-confirmed candidates
                            val sourceTaintParams = taintParams(source, pair.sourceParameterIndexes)
                            for (cand <- reachableCandidates if sinkFullName.isEmpty) {
                                try {
                                    val arguments = cand.argument.l
                                    val positionMatchedArguments =
                                        if (pair.operandStartLine.isEmpty) Nil
                                        else arguments.filter { arg =>
                                            val (endLine, endCol) = inferredEndPosition(
                                                arg.lineNumber, arg.columnNumber, arg.code
                                            )
                                            overlaps(
                                                arg.lineNumber, arg.columnNumber, endLine, endCol,
                                                pair.operandStartLine, pair.operandStartCol,
                                                pair.operandEndLine, pair.operandEndCol
                                            )
                                        }
                                    val codeMatchedArguments =
                                        if (pair.operandCode.trim.isEmpty) Nil
                                        else arguments.filter(_.code.trim == pair.operandCode.trim)
                                    val sinkArgCand =
                                        if (positionMatchedArguments.nonEmpty) positionMatchedArguments
                                        else if (codeMatchedArguments.nonEmpty) codeMatchedArguments
                                        else arguments
                                    val flows =
                                        if (sourceTaintParams.isEmpty) List.empty
                                        else sinkArgCand.iterator.reachableByFlows(sourceTaintParams).l
                                    // Sanitized when every flow passes a sanitizer; report only
                                    // if at least one clean (unsanitized) path reaches the sink.
                                    val cleanFlows =
                                        if (sanitizers.isEmpty) flows
                                        else flows.filter(p => !p.elements.exists {
                                            case c: Call => isSanitizerCall(c)
                                            case _ => false
                                        })
                                    if (cleanFlows.nonEmpty) {
                                        // Count the call nodes on the shortest data-flow path between the source and the sink.
                                        val bestFlow = cleanFlows.minBy(_.elements.size)
                                        sinkCallNodeCount = bestFlow.elements.collect {
                                            case c: Call => c
                                        }.size
                                        sinkFullName = Some(cand.method.fullName)
                                        callNode = Some(cand)
                                    }
                                } catch {
                                    case _: Exception => // skip this candidate
                                }
                            }

                            if (sinkFullName.isDefined && callNode.isDefined) {
                                val sinkOpt = cpg.method.fullNameExact(sinkFullName.get).headOption
                                if (sinkOpt.isDefined) {
                                    val sink = sinkOpt.get
                                    val results = mutable.ArrayBuffer[String]()

                                    if (source.id == sink.id) {
                                        val methodDefinition = getMethodDefinition(source)
                                        val jsonObj = s"""{"methodname":"${esc(source.name)}","filename":"${esc(source.filename)}","isExternal":"${source.isExternal}","methodLineNumberStart":"${source.lineNumber.getOrElse("")}","methodLineNumberEnd":"${source.lineNumberEnd.getOrElse("")}","code":"${esc(methodDefinition)}","calleeLineNumber":""}"""
                                        results.append(jsonObj)
                                    } else {
                                        // BFS to find path
                                        val queue = mutable.Queue[Method](source)
                                        val visited = mutable.Set[Long](source.id)
                                        val parent = mutable.Map[Long, Long]()
                                        var found = false

                                        while (queue.nonEmpty && !found) {
                                            val current = queue.dequeue()
                                            for (callee <- getCallees(current) if !visited.contains(callee.id)) {
                                                visited += callee.id
                                                parent(callee.id) = current.id
                                                queue.enqueue(callee)
                                                if (callee.id == sink.id) found = true
                                            }
                                        }

                                        if (found) {
                                            val path = mutable.ListBuffer[Method]()
                                            var curId = sink.id
                                            while (parent.contains(curId)) {
                                                path.prepend(cpg.method.id(curId).head)
                                                curId = parent(curId)
                                            }
                                            path.prepend(source)

                                            path.zipWithIndex.foreach { case (m, idx) =>
                                                val methodDefinition = getMethodDefinition(m)
                                                val (calleeCode, calleeLineNumber2) = if (idx < path.size - 1) {
                                                    val next = path(idx + 1)
                                                    // Try exact fullName match first
                                                    val callsToNext = m.call.filter(_.methodFullName == next.fullName).l
                                                    val resolvedCalls = if (callsToNext.nonEmpty) callsToNext else {
                                                        // Fallback: match by short method name (handles interface dispatch, overloads)
                                                        m.call.filter(_.name == next.name).l
                                                    }
                                                    if (resolvedCalls.nonEmpty) {
                                                        val bestCall = resolvedCalls.head
                                                        (bestCall.code, bestCall.lineNumber.getOrElse(m.lineNumber.getOrElse("")).toString)
                                                    } else ("", m.lineNumber.getOrElse("").toString)
                                                } else (callNode.get.code, lineNumber.toString)
                                                val jsonObj = s"""{"methodname":"${esc(m.name)}","filename":"${esc(m.filename)}","isExternal":"${m.isExternal}","methodLineNumberStart":"${m.lineNumber.getOrElse("")}","methodLineNumberEnd":"${m.lineNumberEnd.getOrElse("")}","code":"${esc(methodDefinition)}","calleeCode":"${esc(calleeCode)}","calleeLineNumber":"${calleeLineNumber2}"}"""
                                                results.append(jsonObj)
                                            }
                                        }
                                    }

                                    if (results.nonEmpty) {
                                        val pathJson = results.mkString("[", ",", "]")
                                        val entryJson = s"""{"source":"${esc(sourceFullName)}","lineNumber":$lineNumber,"fileName":"${esc(fileName)}","ruleId":"${esc(pair.ruleId)}","sinkId":"${esc(pair.sinkId)}","callNodeCount":$sinkCallNodeCount,"path":$pathJson}"""
                                        allResults.append(entryJson)
                                    }
                                }
                            } else {
                                skippedNoData += 1
                            }
                        }
                    }
                }
            } catch {
                case e: Exception =>
                    println(s"[batch] Error processing pair $sourceFullName -> $fileName:$lineNumber : ${e.getMessage}")
            }
        }
    }

    println(s"[batch] Done. Processed: $processed, Results: ${allResults.length}, Skipped BFS: $skippedBfs, Skipped no-data: $skippedNoData")

    // Write results to output file
    val outputJson = allResults.mkString("[", ",", "]")
    val writer = new java.io.PrintWriter(new java.io.File(outputPath))
    try { writer.write(outputJson) } finally { writer.close() }
}
