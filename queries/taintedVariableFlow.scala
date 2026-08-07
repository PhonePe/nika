import scala.collection.mutable
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method, MethodParameterIn, Expression}
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
  if (s == null) ""
  else {
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
}
def findTaintedVariableFlows(paramsPath: String, outputPath: String): Unit = {
  val params = loadParams(paramsPath)
  val lines = params.getOrElse("pair", Seq.empty).toArray
  val sourceAnnotations = params.getOrElse("sourceAnnotation", Nil).map(_.stripPrefix("@")).toSet
  val requestAccessors = params.getOrElse("requestAccessor", Nil).toSet
  val sinkNames = params.getOrElse("sinkName", Nil).toSet
  val receiverOnlyNames = params.getOrElse("receiverOnlySink", Nil).toSet

  val frameworkTypeMarkers = Seq(
    "HttpServletResponse",
    "ServletResponse",
    "HttpServletRequest",
    "ServletRequest",
    "HttpSession",
    "javax.ws.rs.core.Response",
    "jakarta.ws.rs.core.Response",
    "org.springframework.ui.Model",
    "org.springframework.ui.ModelMap",
    "org.springframework.validation.BindingResult",
    "org.springframework.validation.Errors",
    "org.springframework.web.servlet.mvc.support.RedirectAttributes",
    "org.springframework.web.util.UriComponentsBuilder",
    "java.security.Principal",
    "org.springframework.security.core.Authentication",
    "java.util.Locale"
  )

  def typeContains(typeFullName: String, marker: String): Boolean =
    typeFullName != null && (typeFullName == marker || typeFullName.endsWith("." + marker) || typeFullName.contains(marker))

  def isFrameworkParam(p: MethodParameterIn): Boolean =
    frameworkTypeMarkers.exists(marker => typeContains(p.typeFullName, marker))

  def isAnnotatedRequestParam(p: MethodParameterIn): Boolean =
    sourceAnnotations.nonEmpty && p.annotation.name(sourceAnnotations.toSeq: _*).nonEmpty

  def isRequestControlledParam(p: MethodParameterIn): Boolean =
    p.name != "this" && !isFrameworkParam(p) && (isAnnotatedRequestParam(p) || Option(p.name).exists(_.nonEmpty))

  def isRequestAccessor(c: Call): Boolean = {
    val code = Option(c.code).getOrElse("")
    val methodFullName = Option(c.methodFullName).getOrElse("")
    requestAccessors.contains(c.name) &&
      (methodFullName.contains("HttpServletRequest") || code.contains("." + c.name + "("))
  }

  def nonReceiverArgs(c: Call): List[Expression] = {
    val receiverIds = c.receiver.l.map(_.id).toSet
    c.argument.l.filterNot(arg => receiverIds.contains(arg.id)).sortBy(_.argumentIndex)
  }

  def isFluentReceiver(n: Expression): Boolean =
    n.isInstanceOf[Call] && !n.asInstanceOf[Call].name.startsWith("<operator>")

  // Candidate nodes that carry data into the sink. For receiver-only sinks the
  // tainted value flows through the receiver (e.g. url.openConnection()); for
  // regular sinks it flows through the arguments (and non-fluent receivers).
  def sinkTargetNodes(c: Call): List[Expression] = {
    val name = Option(c.name).getOrElse("")
    if (receiverOnlyNames.contains(name)) c.receiver.l
    else {
      val args = nonReceiverArgs(c)
      val nonFluentReceivers = c.receiver.l.filterNot(isFluentReceiver)
      (args ++ nonFluentReceivers).distinct
    }
  }

  def simpleIdentifier(code: String): Option[String] = {
    val value = Option(code).getOrElse("").trim
    if (value.matches("[A-Za-z_$][A-Za-z0-9_$]*")) Some(value) else None
  }

  def namesInExpr(expr: Expression): Set[String] =
    (expr.ast.isIdentifier.name.l ++ simpleIdentifier(expr.code).toList).toSet

  def hasRequestAccessor(expr: Expression): Boolean =
    expr.ast.isCall.exists(isRequestAccessor)

  def sourceSummary(method: Method) = {
    val methodParams = method.parameter.filter(isRequestControlledParam).l
    val labels = mutable.Map[String, String]()
    val flows = mutable.Map[String, String]()

    methodParams.foreach { p =>
      val kind =
        p.annotation.name.l.find(a => sourceAnnotations.contains(a)).map("@" + _).getOrElse("request parameter")
      labels.put(p.name, kind)
      labels.put(p.code, kind)
      flows.put(p.name, s"$kind ${p.name}")
    }

    (mutable.LinkedHashSet(methodParams.map(_.name): _*), labels.toMap, flows)
  }

  def assignmentTarget(c: Call): Option[String] =
    c.argument.argumentIndex(1).code.headOption.flatMap(simpleIdentifier)

  def assignmentRhs(c: Call): Option[Expression] =
    c.argument.argumentIndex(2).headOption

  // Propagate taint through local assignments that occur before the sink line.
  // Each newly tainted variable records the full flow expression that produced
  // it, so the final flow summary reads as a step-by-step propagation chain.
  def propagateLocalAssignments(
      method: Method,
      sinkLine: Int,
      initialTainted: mutable.LinkedHashSet[String],
      initialFlows: mutable.Map[String, String]
  ): (mutable.LinkedHashSet[String], mutable.Map[String, String]) = {
    val tainted = mutable.LinkedHashSet[String]() ++ initialTainted
    val flows = mutable.Map[String, String]() ++ initialFlows
    val assignments = method.call.name("<operator>.assignment").l
      .filter(c => c.lineNumber.exists(_ <= sinkLine))
      .sortBy(c => c.lineNumber.getOrElse(0))

    var changed = true
    while (changed) {
      changed = false
      assignments.foreach { assignment =>
        val lhsOpt = assignmentTarget(assignment)
        val rhsOpt = assignmentRhs(assignment)
        (lhsOpt, rhsOpt) match {
          case (Some(lhs), Some(rhs)) if !tainted.contains(lhs) =>
            val rhsNames = namesInExpr(rhs)
            val matched = rhsNames.find(tainted.contains)
            if (matched.isDefined || hasRequestAccessor(rhs)) {
              tainted += lhs
              val sourceFlow = matched.flatMap(flows.get).getOrElse(rhs.code)
              flows.put(lhs, s"$sourceFlow -> $lhs = ${rhs.code}")
              changed = true
            }
          case _ =>
        }
      }
    }
    (tainted, flows)
  }

  // Determine whether a tainted variable reaches the given sink target node.
  // Returns (taintedVariable, flowSummarySuffix, taintedVariableKind).
  def flowIntoTarget(
      target: Expression,
      tainted: mutable.LinkedHashSet[String],
      flows: mutable.Map[String, String]
  ): Option[(String, String, String)] = {
    val targetNames = namesInExpr(target)
    targetNames.find(tainted.contains).map { name =>
      val sourceFlow = flows.getOrElse(name, name)
      val summary = if (target.code == name) sourceFlow else s"$sourceFlow -> ${target.code}"
      (name, summary, "local-variable")
    }.orElse {
      if (hasRequestAccessor(target)) Some((target.code, target.code, "request-accessor"))
      else None
    }
  }

  def selectSinkCalls(calls: List[Call]): List[Call] =
    if (sinkNames.isEmpty) {
      // Without an explicit sink-name allowlist the real sink is a method
      // invocation, never an assignment/operator. Drop operator calls (e.g.
      // `<operator>.assignment`) so the LHS of `var x = sink(...)` is not
      // mistaken for the tainted input, and consider the outermost call first
      // so the reported sink argument is the value passed into the sink.
      val nonOperator = calls.filterNot(c => Option(c.name).getOrElse("").startsWith("<operator>"))
      val chosen = if (nonOperator.nonEmpty) nonOperator else calls
      chosen.sortBy(c => -Option(c.code).getOrElse("").length)
    } else {
      val matched = calls.filter(c => sinkNames.contains(Option(c.name).getOrElse("")))
      if (matched.nonEmpty) matched else calls
    }

  val results = mutable.ArrayBuffer[String]()

  for (line <- lines) {
    val parts = line.split("\t")
    if (parts.length >= 3) {
      val sourceFullName = parts(0)
      val lineNumber = parts(1).toInt
      val fileName = parts(2)
      val regexFileName = ".*" + Pattern.quote(fileName) + "$"

      try {
        val calls = cpg.file.name(regexFileName).method.call.filter(_.lineNumber.exists(_ == lineNumber)).l

        if (calls.nonEmpty) {
          val sinkCalls = selectSinkCalls(calls)
          var emitted = false

          for (call <- sinkCalls if !emitted) {
            val enclosing = call.method
            val (requestSources, labels, initialFlows) = sourceSummary(enclosing)
            val targets = sinkTargetNodes(call)
            if (targets.nonEmpty) {
              val (tainted, flows) = propagateLocalAssignments(enclosing, lineNumber, requestSources, initialFlows)
              val targetFlow = targets.flatMap(target => flowIntoTarget(target, tainted, flows)).headOption
              if (targetFlow.isDefined) {
                val (taintedVar, flowSummarySuffix, taintedVarKind) = targetFlow.get
                val sourceKind =
                  labels.getOrElse(taintedVar, if (taintedVar.contains("(")) "request accessor" else "request parameter")
                val sinkArg = targets.headOption.map(_.code).getOrElse("")
                val flowSummary = s"$flowSummarySuffix -> ${Option(call.code).getOrElse("")}"
                val confidence = if (taintedVarKind == "request-accessor") "accessor-reachability" else "cpg-tainted-variable"
                results.append(
                  s"""{"source":"${esc(sourceFullName)}","lineNumber":$lineNumber,"fileName":"${esc(fileName)}","requestControlled":true,"taintedVariable":"${esc(taintedVar)}","taintedVariableKind":"${esc(taintedVarKind)}","sourceParam":"${esc(taintedVar)}","sourceKind":"${esc(sourceKind)}","sinkArgument":"${esc(sinkArg)}","flowSummary":"${esc(flowSummary)}","flowConfidence":"${esc(confidence)}","sinkCode":"${esc(call.code)}"}"""
                )
                emitted = true
              }
            }
          }

          if (!emitted && sinkCalls.nonEmpty) {
            val sinkArg = sinkCalls.flatMap(sinkTargetNodes).headOption.map(_.code).getOrElse("")
            results.append(
              s"""{"source":"${esc(sourceFullName)}","lineNumber":$lineNumber,"fileName":"${esc(fileName)}","requestControlled":false,"taintedVariable":"","taintedVariableKind":"","sinkArgument":"${esc(sinkArg)}","flowSummary":"${esc("No request-controlled tainted variable reaches the sink argument in the CPG data-flow query.")}","flowConfidence":"not_request_controlled","sinkCode":"${esc(sinkCalls.head.code)}"}"""
            )
          }
        }
      } catch {
        case e: Exception =>
          println(s"[tainted-variable-flow] error processing $sourceFullName -> $fileName:$lineNumber : ${e.getMessage}")
      }
    }
  }

  val writer = new java.io.PrintWriter(new java.io.File(outputPath))
  try { writer.write(results.mkString("[", ",", "]")) } finally { writer.close() }
}
