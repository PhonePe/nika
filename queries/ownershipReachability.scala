import scala.collection.mutable
import io.shiftleft.codepropertygraph.generated.nodes.{Method, Call}

def loadParams(path: String): Map[String, Seq[String]] = {
  val decoder = java.util.Base64.getDecoder
  val source = scala.io.Source.fromFile(path)
  try {
    source.getLines().map(_.trim).filter(_.nonEmpty).toList.flatMap { line =>
      val tab = line.indexOf('\t')
      if (tab < 0) None
      else {
        val key = line.substring(0, tab)
        val value = new String(decoder.decode(line.substring(tab + 1)), "UTF-8")
        Some((key, value))
      }
    }.groupBy(_._1).map { case (k, kvs) => (k, kvs.map(_._2)) }
  } finally source.close()
}

def findOwnershipReachable(
    paramsPath: String,
    outputPath: String
): Unit = {
  val params = loadParams(paramsPath)
  val principalMarkers = params.getOrElse("principalMarker", Nil).toSet
  val principalTypes = params.getOrElse("principalType", Nil).toSet
  val principalAnnotations = params.getOrElse("principalAnnotation", Nil).toSet
  val identifierNames = params.getOrElse("identifier", Nil).toSet
  val explicitFunctions = params.getOrElse("explicitFunction", Nil).toSet
  val ownershipAnnotations = params.getOrElse("ownershipAnnotation", Nil).toSet
  val requireIdentifierParam = params.getOrElse("requireIdentifierParam", Nil).headOption.contains("true")
  val requireComparison = params.getOrElse("requireComparison", Nil).headOption.contains("true")
  val matchGenericId = params.getOrElse("matchGenericId", Nil).headOption.contains("true")

  def esc(s: String): String =
    if (s == null) ""
    else s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")

  def norm(s: String): String = s.toLowerCase.replaceAll("[^a-z0-9]", "")
  val normIds = identifierNames.map(norm).filter(_.nonEmpty)
  // A bare `id` or a `*Id` suffix
  def isGenericId(name: String): Boolean = {
    val n = if (name == null) "" else name
    n == "id" || n == "ID" || n.endsWith("Id") || n.endsWith("_id")
  }
  def matchesId(name: String): Boolean = {
    val x = norm(name)
    (x.nonEmpty && normIds.exists(id => x == id || x.endsWith(id))) ||
      (matchGenericId && isGenericId(name))
  }
  def fieldFromAccessor(n: String): String =
    if (n.startsWith("get")) n.drop(3) else if (n.startsWith("is")) n.drop(2) else n

  val markerSeq = principalMarkers.toSeq
  val typeSeq = principalTypes.toSeq
  val annoSeq = principalAnnotations.toSeq
  val comparisonNames = Set("equals", "compareTo", "contains", "containsKey", "containsValue")

  def typeMatches(typeFullName: String): Boolean =
    typeFullName != null && typeSeq.exists(t => typeFullName == t || typeFullName.endsWith("." + t))

  // True when the call's receiver is of a trusted type, e.g. internalCtx.getUserId().
  def receiverIsTrusted(c: Call): Boolean =
    c.receiver.isCall.typeFullName.exists(typeMatches) ||
      c.receiver.isIdentifier.typeFullName.exists(typeMatches)

  def isPrincipalCall(c: Call): Boolean =
    (markerSeq.nonEmpty && markerSeq.contains(c.name)) ||
      (markerSeq.nonEmpty && Option(c.code).exists(code => markerSeq.exists(code.contains))) ||
      typeMatches(c.typeFullName) ||
      receiverIsTrusted(c)

  def isPrincipalParam(p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn): Boolean =
    typeMatches(p.typeFullName) ||
      (annoSeq.nonEmpty && p.annotation.name(annoSeq: _*).nonEmpty)

  // An identifier accessor on a non-trusted object, e.g. requestBody.getUserId().
  def isIdAccessor(c: Call): Boolean = {
    val n = c.name
    (n.startsWith("get") || n.startsWith("is")) && matchesId(fieldFromAccessor(n)) && !receiverIsTrusted(c)
  }

  def isComparison(c: Call): Boolean =
    comparisonNames.contains(c.name) ||
      Option(c.methodFullName).exists(_.startsWith("<operator>.equals")) ||
      Option(c.methodFullName).exists(_.startsWith("<operator>.notEquals"))

  def referencesPrincipal(m: Method): Boolean =
    m.call.exists(isPrincipalCall) ||
      m.parameter.exists(isPrincipalParam) ||
      m.ast.isIdentifier.exists(i => typeMatches(i.typeFullName))

  def comparesPrincipalToId(m: Method): Boolean = {
    // no comparison call -> cannot match (avoids dataflow).
    if (!m.call.exists(isComparison)) return false

    val principalCalls = m.call.filter(isPrincipalCall).l
    val principalParams = m.parameter.filter(isPrincipalParam).l
    val principalIdents = m.ast.isIdentifier.filter(i => typeMatches(i.typeFullName)).l
    val idParams = m.parameter.filter(p => matchesId(p.name)).l
    val idAccessors = m.call.filter(isIdAccessor).l

    val hasPrincipal = principalCalls.nonEmpty || principalParams.nonEmpty || principalIdents.nonEmpty
    val hasId = idParams.nonEmpty || idAccessors.nonEmpty
    if (!hasPrincipal || !hasId) false
    else {
      m.call.filter(isComparison).exists { c =>
        val fromPrincipal =
          (principalCalls.nonEmpty && c.argument.reachableByFlows(principalCalls).nonEmpty) ||
            (principalParams.nonEmpty && c.argument.reachableByFlows(principalParams).nonEmpty) ||
            (principalIdents.nonEmpty && c.argument.reachableByFlows(principalIdents).nonEmpty)
        val fromId =
          (idParams.nonEmpty && c.argument.reachableByFlows(idParams).nonEmpty) ||
            (idAccessors.nonEmpty && c.argument.reachableByFlows(idAccessors).nonEmpty)
        fromPrincipal && fromId
      }
    }
  }

  // Principal and identifier both flow into the same multi-arg call, e.g.repo.findByIdAndOwner(id, currentUser)
  def scopesQueryByPrincipalAndId(m: Method): Boolean = {
    val principalCalls = m.call.filter(isPrincipalCall).l
    val principalParams = m.parameter.filter(isPrincipalParam).l
    val principalIdents = m.ast.isIdentifier.filter(i => typeMatches(i.typeFullName)).l
    val idParams = m.parameter.filter(p => matchesId(p.name)).l
    val idAccessors = m.call.filter(isIdAccessor).l

    val hasPrincipal = principalCalls.nonEmpty || principalParams.nonEmpty || principalIdents.nonEmpty
    val hasId = idParams.nonEmpty || idAccessors.nonEmpty
    if (!hasPrincipal || !hasId) false
    else {
      m.call.filter(c => !isPrincipalCall(c) && !isIdAccessor(c) && c.argument.size >= 2).exists { c =>
        val fromPrincipal =
          (principalCalls.nonEmpty && c.argument.reachableByFlows(principalCalls).nonEmpty) ||
            (principalParams.nonEmpty && c.argument.reachableByFlows(principalParams).nonEmpty) ||
            (principalIdents.nonEmpty && c.argument.reachableByFlows(principalIdents).nonEmpty)
        val fromId =
          (idParams.nonEmpty && c.argument.reachableByFlows(idParams).nonEmpty) ||
            (idAccessors.nonEmpty && c.argument.reachableByFlows(idAccessors).nonEmpty)
        fromPrincipal && fromId
      }
    }
  }

  val discoveredIds: Set[Long] = cpg.method.filter { m =>
    if (requireComparison) comparesPrincipalToId(m) || scopesQueryByPrincipalAndId(m)
    else {
      val hasId = !requireIdentifierParam || m.parameter.name.exists(matchesId)
      hasId && referencesPrincipal(m)
    }
  }.id.toSet

  // Explicit ownership functions
  val explicitSpecs: Seq[(String, Option[String], Option[String])] =
    explicitFunctions.toSeq.map { e =>
      val parts = e.split("::", -1)
      val name = parts(0)
      val repoOpt = if (parts.length >= 2 && parts(1).nonEmpty) Some(parts(1).toLowerCase) else None
      val resOpt = if (parts.length >= 3 && parts(2).nonEmpty) Some(parts(2)) else None
      (name, repoOpt, resOpt)
    }
  def fileMatchesRepo(filename: String, repo: String): Boolean =
    filename != null && filename.toLowerCase.contains(repo)

  // A configured name matches a method by simple name or by FQN.
  def methodMatchesName(m: Method, name: String): Boolean =
    if (name.contains(".")) {
      val qualified = m.fullName.split(":").head
      qualified == name || qualified.endsWith("." + name) || m.fullName == name
    } else m.name == name

  // For each matching explicit method: the resources it guards, and whether it is generic.
  val explicitAllIds = mutable.Set[Long]()
  val explicitGenericIds = mutable.Set[Long]()
  val explicitResourceById = mutable.Map[Long, mutable.Set[String]]()
  if (explicitSpecs.nonEmpty) {
    cpg.method.filter(m => explicitSpecs.exists { case (fn, _, _) => methodMatchesName(m, fn) }).foreach { m =>
      val matching = explicitSpecs.filter {
        case (fn, repoOpt, _) => methodMatchesName(m, fn) && repoOpt.forall(r => fileMatchesRepo(m.filename, r))
      }
      if (matching.nonEmpty) {
        explicitAllIds += m.id
        if (matching.exists(_._3.isEmpty)) explicitGenericIds += m.id
        val resources = matching.flatMap(_._3)
        if (resources.nonEmpty)
          explicitResourceById.getOrElseUpdate(m.id, mutable.Set[String]()) ++= resources
      }
    }
  }

  // Auto-discovered methods and resource-less explicit specs guard any identifier.
  val genericOwnershipIds: Set[Long] = discoveredIds ++ explicitGenericIds.toSet
  val allOwnershipIds: Set[Long] = genericOwnershipIds ++ explicitResourceById.keySet.toSet

  // A resource matches when an identifier the endpoint exposes equals it or ends with it.
  def resourceMatchesEndpoint(endpointIds: Set[String], resource: String): Boolean = {
    val b = norm(resource)
    b.nonEmpty && endpointIds.exists { eid =>
      val a = norm(eid)
      a.nonEmpty && (a == b || a.endsWith(b))
    }
  }
  def compatible(methodId: Long, endpointIds: Set[String]): Boolean =
    genericOwnershipIds.contains(methodId) ||
      explicitResourceById.get(methodId).exists(_.exists(r => resourceMatchesEndpoint(endpointIds, r)))

  val endpointEntries: List[(String, Set[String])] =
    params.getOrElse("endpoint", Nil).toList.map { line =>
      val tab = line.indexOf('\t')
      if (tab < 0) (line, Set.empty[String])
      else {
        val fullName = line.substring(0, tab)
        val ids = line.substring(tab + 1).split(",").map(_.trim).filter(_.nonEmpty).toSet
        (fullName, ids)
      }
    }
  val endpoints = endpointEntries.map(_._1)

  val results = mutable.ArrayBuffer[String]()
  val handled = mutable.Set[String]()

  // Ownership annotations.
  val annotationSpecs: Seq[(String, Option[String], Option[String])] =
    ownershipAnnotations.toSeq.map { e =>
      val parts = e.split("::", -1)
      val name = parts(0)
      val repoOpt = if (parts.length >= 2 && parts(1).nonEmpty) Some(parts(1).toLowerCase) else None
      val resOpt = if (parts.length >= 3 && parts(2).nonEmpty) Some(parts(2)) else None
      (name, repoOpt, resOpt)
    }
  if (annotationSpecs.nonEmpty) {
    for ((ep, epIds) <- endpointEntries if !handled.contains(ep)) {
      cpg.method.fullNameExact(ep).headOption.foreach { m =>
        val matched = m.annotation.l.flatMap { a =>
          val fn = a.fullName
          val spec = annotationSpecs.find {
            case (name, repoOpt, resOpt) =>
              (a.name == name || (fn != null && (fn == name || fn.endsWith("." + name)))) &&
                repoOpt.forall(r => fileMatchesRepo(m.filename, r)) &&
                resOpt.forall(r => resourceMatchesEndpoint(epIds, r))
          }
          spec.map(_ => a.name)
        }.headOption
        matched.foreach { annoName =>
          results.append(
            s"""{"endpoint":"${esc(ep)}","protected":true,"reachedMethod":"@${esc(annoName)}",""" +
              s""""isExplicit":true,"annotation":"${esc(annoName)}","signature":"${esc(m.code)}","chain":[]}"""
          )
          handled += ep
        }
      }
    }
  }

  if (allOwnershipIds.nonEmpty && endpoints.nonEmpty) {
    // The endpoint method is itself an ownership method (reachability skips self-loops).
    for ((ep, epIds) <- endpointEntries) {
      cpg.method.fullNameExact(ep).headOption.foreach { m =>
        if (allOwnershipIds.contains(m.id) && compatible(m.id, epIds) && !handled.contains(ep)) {
          val isExplicit = explicitAllIds.contains(m.id)
          results.append(
            s"""{"endpoint":"${esc(ep)}","protected":true,"reachedMethod":"${esc(m.name)}",""" +
              s""""isExplicit":$isExplicit,"signature":"${esc(m.code)}","chain":["${esc(m.name)}"]}"""
          )
          handled += ep
        }
      }
    }

    def ownershipTrav = cpg.method.filter(m => allOwnershipIds.contains(m.id))

    for ((endpointFullName, epIds) <- endpointEntries if !handled.contains(endpointFullName)) {
      try {
        val chains =
          ownershipTrav
            .reachableByCallGraphWithChain(cpg.method.fullNameExact(endpointFullName))
            .l
            .filter(_.nonEmpty)
        val compatibleChains = chains.filter(ch => compatible(ch.last.id, epIds))
        if (compatibleChains.nonEmpty) {
          val chain = compatibleChains.minBy(_.size)
          val reached = chain.last
          val isExplicit = explicitAllIds.contains(reached.id)
          val chainJson = chain.map(m => "\"" + esc(m.name) + "\"").mkString("[", ",", "]")
          results.append(
            s"""{"endpoint":"${esc(endpointFullName)}","protected":true,""" +
              s""""reachedMethod":"${esc(reached.name)}","isExplicit":$isExplicit,""" +
              s""""signature":"${esc(reached.code)}","chain":$chainJson}"""
          )
        }
      } catch {
        case e: Exception =>
          println(s"[ownership] reachability error for $endpointFullName: ${e.getMessage}")
      }
    }
  }

  val outputJson = results.mkString("[", ",", "]")
  val writer = new java.io.PrintWriter(new java.io.File(outputPath))
  try { writer.write(outputJson) } finally { writer.close() }
}
