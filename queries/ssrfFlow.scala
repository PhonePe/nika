import scala.collection.mutable
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method, Expression}
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

def findSsrfFlows(paramsPath: String, outputPath: String): Unit = {
  val params = loadParams(paramsPath)
  val lines = params.getOrElse("pair", Seq.empty).toArray
  val sinkNames = params.getOrElse("sinkName", Nil).toSet
  val receiverOnlyNames = params.getOrElse("receiverOnlySink", Nil).toSet

  def nonReceiverArgs(c: Call): List[Expression] = {
    val receiverIds = c.receiver.l.map(_.id).toSet
    c.argument.l.filterNot(a => receiverIds.contains(a.id)).sortBy(_.argumentIndex)
  }

  def isFluentReceiver(n: Expression): Boolean =
    n.isInstanceOf[Call] && !n.asInstanceOf[Call].name.startsWith("<operator>")

  def destinationNodes(c: Call): List[Expression] = {
    val name = Option(c.name).getOrElse("")
    if (receiverOnlyNames.contains(name)) c.receiver.l
    else {
      val args = nonReceiverArgs(c)
      val nonFluentReceivers = c.receiver.l.filterNot(isFluentReceiver)
      args ++ nonFluentReceivers
    }
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
        val sourceOpt = cpg.method.fullNameExact(sourceFullName).headOption
        val calls = cpg.file.name(regexFileName).method.call.filter(_.lineNumber.exists(_ == lineNumber)).l

        if (sourceOpt.isDefined && calls.nonEmpty) {
          val source = sourceOpt.get
          val sourceParams = source.parameter.l

          val sinkCalls =
            if (sinkNames.isEmpty) calls
            else calls.filter(c => sinkNames.contains(Option(c.name).getOrElse("")))

          val evaluable = sinkCalls.map(c => (c, destinationNodes(c))).filter(_._2.nonEmpty)

          if (evaluable.nonEmpty && sourceParams.nonEmpty) {
            var requestControlled = false
            var sinkCode = evaluable.head._1.code
            var sinkArgument = evaluable.head._2.headOption.map(_.code).getOrElse("")

            for ((call, dests) <- evaluable if !requestControlled) {
              val tainted =
                try dests.iterator.reachableByFlows(sourceParams).nonEmpty
                catch { case _: Exception => false }
              if (tainted) {
                requestControlled = true
                sinkCode = call.code
                sinkArgument = dests.headOption.map(_.code).getOrElse("")
              }
            }

            results.append(
              s"""{"source":"${esc(sourceFullName)}","lineNumber":$lineNumber,"fileName":"${esc(fileName)}","requestControlled":$requestControlled,"sinkArgument":"${esc(sinkArgument)}","sinkCode":"${esc(sinkCode)}"}"""
            )
          }
        }
      } catch {
        case e: Exception =>
          println(s"[ssrf-flow] error processing $sourceFullName -> $fileName:$lineNumber : ${e.getMessage}")
      }
    }
  }

  val writer = new java.io.PrintWriter(new java.io.File(outputPath))
  try { writer.write(results.mkString("[", ",", "]")) } finally { writer.close() }
}
