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
    def taintParams(source: Method): List[io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn] = {
        taintParamCache.getOrElseUpdate(source.id, {
            if (excludeAnnoSet.isEmpty && excludeTypeSet.isEmpty) source.parameter.l
            else source.parameter.filterNot(isExcludedParam).l
        })
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
        val parts = line.split("\t")
        if (parts.length >= 3) {
            val sourceFullName = parts(0)
            val lineNumber = parts(1).toInt
            val fileName = parts(2)
            val regexFileName = s".*$fileName"

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
                    val callNodeCandidates = sinkCallCache.getOrElseUpdate((fileName, lineNumber),
                        cpg.file.name(regexFileName).method.call.filter(_.lineNumber.exists(_ == lineNumber)).l
                    )

                    if (callNodeCandidates.isEmpty) {
                        skippedNoData += 1
                    } else {
                        // Find which candidate's method is the sink
                        var sinkFullName: Option[String] = None
                        var callNode: Option[Call] = None

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
                            val sourceTaintParams = taintParams(source)
                            for (cand <- reachableCandidates if sinkFullName.isEmpty) {
                                try {
                                    val sinkArgCand = cand.argument
                                    // Sanitized when every flow passes a sanitizer; report only
                                    // if at least one clean (unsanitized) path reaches the sink.
                                    val reachable =
                                        if (sourceTaintParams.isEmpty) false
                                        else {
                                            val flows = sinkArgCand.reachableByFlows(sourceTaintParams)
                                            if (sanitizers.isEmpty) flows.nonEmpty
                                            else flows.exists(p => !p.elements.exists {
                                                case c: Call => isSanitizerCall(c)
                                                case _ => false
                                            })
                                        }
                                    if (reachable) {
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
                                        val entryJson = s"""{"source":"${esc(sourceFullName)}","lineNumber":$lineNumber,"fileName":"${esc(fileName)}","path":$pathJson}"""
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
