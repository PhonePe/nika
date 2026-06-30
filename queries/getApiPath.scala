def getAPIData(sourceAnnotations: Set[String], servletMethods: Set[String], sourceMethodFullNames: Set[String]) : String = {
    val results = scala.collection.mutable.ArrayBuffer.empty[String]
    val annotationsToCheck = sourceAnnotations.toSeq

    def esc(s: String): String = s.replace("\\", "\\\\")
                                  .replace("\"", "\\\"")
                                  .replace("\n", "\\n")
                                  .replace("\r", "\\r")
                                  .replace("\t", "\\t")

    cpg.method.where(_.annotation.name(annotationsToCheck*)).foreach { m =>
        val classASTNode = Iterator(m).repeat(_.astParent)(_.until(_.isTypeDecl)).headOption
        if(classASTNode.isDefined){
            val classNode = classASTNode.get.asInstanceOf[TypeDecl]
            val classPathLiterals = classNode.annotation.name(annotationsToCheck*).ast.collect{ case apa: AnnotationParameterAssign => apa }
                .ast.collect{ case apl: AnnotationLiteral => apl }
            val classAPIPathOpt = classPathLiterals.headOption.map(_.name).filter(_.nonEmpty)
            // Proceed only if class is also annotated with source annotations
            if(classAPIPathOpt.isDefined){
                var classAPIPath = classAPIPathOpt.get
                if(classAPIPath.endsWith("/")) {
                    classAPIPath = classAPIPath.dropRight(1)
                }
                val methodAPIPath = m.annotation.name(annotationsToCheck*).ast.collect{ case apa: AnnotationParameterAssign => apa }
                    .ast.collect{ case apl: AnnotationLiteral => apl }.headOption.map(_.name).getOrElse("")

                val outputLine = s"""{ "classAPIPath": "${esc(classAPIPath)}", "methodAPIPath": "${esc(methodAPIPath)}", "classFullName": "${esc(classNode.fullName)}", "methodName": "${esc(m.fullName)}", "lineNumber": "${esc(m.lineNumber.get.toString)}", "lineNumberEnd": "${esc(m.lineNumberEnd.get.toString)}", "fileName": "${esc(m.filename)}", "code": "${esc(m.code)}" }"""

                results.append(outputLine)
            }
            else {
                val methodAPIPath = m.annotation.name(annotationsToCheck*).ast.collect{ case apa: AnnotationParameterAssign => apa }
                    .ast.collect{ case apl: AnnotationLiteral => apl }.headOption.map(_.name).getOrElse("")

                val outputLine = s"""{ "classAPIPath": "", "methodAPIPath": "${esc(methodAPIPath)}", "classFullName": "${esc(classNode.fullName)}", "methodName": "${esc(m.fullName)}", "lineNumber": "${esc(m.lineNumber.get.toString)}", "lineNumberEnd": "${esc(m.lineNumberEnd.get.toString)}", "fileName": "${esc(m.filename)}", "code": "${esc(m.code)}" }"""

                results.append(outputLine)
            }
        }
    }

    // Servlet entry points
    if (servletMethods.nonEmpty) {
        val servletNames = servletMethods.toSeq
        cpg.method.nameExact(servletNames*)
            .where(_.parameter.typeFullName(".*HttpServletRequest"))
            .foreach { m =>
                val classASTNode = Iterator(m).repeat(_.astParent)(_.until(_.isTypeDecl)).headOption
                if(classASTNode.isDefined){
                    val classNode = classASTNode.get.asInstanceOf[TypeDecl]
                    var classAPIPath = classNode.annotation.ast.collect{ case apl: AnnotationLiteral => apl }
                        .map(_.name).find(_.startsWith("/")).getOrElse("")
                    if(classAPIPath.endsWith("/")) {
                        classAPIPath = classAPIPath.dropRight(1)
                    }

                    val outputLine = s"""{ "classAPIPath": "${esc(classAPIPath)}", "methodAPIPath": "", "classFullName": "${esc(classNode.fullName)}", "methodName": "${esc(m.fullName)}", "lineNumber": "${esc(m.lineNumber.get.toString)}", "lineNumberEnd": "${esc(m.lineNumberEnd.get.toString)}", "fileName": "${esc(m.filename)}", "code": "${esc(m.code)}" }"""

                    results.append(outputLine)
                }
            }
    }

    // Arbitrary user-configured sources
    if (sourceMethodFullNames.nonEmpty) {
        val sourceMethodNames = sourceMethodFullNames.toSeq
        cpg.method.fullNameExact(sourceMethodNames*).foreach { m =>
            val classASTNode = Iterator(m).repeat(_.astParent)(_.until(_.isTypeDecl)).headOption
            val classFullName = classASTNode.map(_.asInstanceOf[TypeDecl].fullName).getOrElse("")

            val outputLine = s"""{ "classAPIPath": "", "methodAPIPath": "", "classFullName": "${esc(classFullName)}", "methodName": "${esc(m.fullName)}", "lineNumber": "${esc(m.lineNumber.get.toString)}", "lineNumberEnd": "${esc(m.lineNumberEnd.get.toString)}", "fileName": "${esc(m.filename)}", "code": "${esc(m.code)}" }"""

            results.append(outputLine)
        }
    }

    return results.mkString("[\n", ",\n", "\n]")
}