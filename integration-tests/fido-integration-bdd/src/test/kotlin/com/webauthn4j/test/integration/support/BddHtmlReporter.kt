package com.webauthn4j.test.integration.support

import io.kotest.core.listeners.AfterProjectListener
import io.kotest.core.listeners.AfterTestListener
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.Spec
import io.kotest.core.test.TestCase
import io.kotest.core.test.TestResult
import io.kotest.core.test.TestType
import java.io.File
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.reflect.KClass

/**
 * A custom Kotest listener that generates a single-page BDD HTML report
 * with the full Given/When/Then hierarchy displayed as a tree.
 *
 * Output: {buildDir}/reports/bdd/index.html
 */
class BddHtmlReporter : AfterTestListener, AfterProjectListener {

    private data class TestEntry(
        val testCase: TestCase,
        val result: TestResult,
    )

    private val entries = mutableListOf<TestEntry>()

    override suspend fun afterAny(testCase: TestCase, result: TestResult) {
        synchronized(entries) {
            entries.add(TestEntry(testCase, result))
        }
    }

    override suspend fun afterProject() {
        if (entries.isEmpty()) return

        val buildDir = System.getProperty("gradle.build.dir") ?: "build"
        val outputDir = File(buildDir, "reports/bdd")
        outputDir.mkdirs()

        val html = generateHtml()
        File(outputDir, "index.html").writeText(html)
    }

    private fun generateHtml(): String {
        // Group entries by spec class, then by @Tags category
        val specGroups = entries.groupBy { it.testCase.spec::class }
        val categoryGroups = specGroups.entries.groupBy { (specClass, _) ->
            specClass.java.getAnnotation(Tags::class.java)?.values?.firstOrNull() ?: "Uncategorized"
        }

        // Count results
        val leafTests = entries.filter { it.testCase.type == TestType.Test }
        val totalTests = leafTests.size
        val passed = leafTests.count { it.result is TestResult.Success }
        val failed = leafTests.count { it.result is TestResult.Failure || it.result is TestResult.Error }
        val skipped = leafTests.count { it.result is TestResult.Ignored }

        val timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))

        return buildString {
            appendLine("<!DOCTYPE html>")
            appendLine("<html lang=\"en\">")
            appendLine("<head>")
            appendLine("<meta charset=\"UTF-8\">")
            appendLine("<title>BDD Specification Report</title>")
            appendLine("<style>")
            appendLine(CSS)
            appendLine("</style>")
            appendLine("</head>")
            appendLine("<body>")
            appendLine("<div class=\"container\">")
            appendLine("<h1>BDD Specification Report</h1>")
            appendLine("<p class=\"timestamp\">Generated: $timestamp</p>")
            appendLine("<div class=\"summary\">")
            appendLine("<span class=\"total\">$totalTests tests</span>")
            if (passed > 0) appendLine("<span class=\"pass-count\">$passed passed</span>")
            if (failed > 0) appendLine("<span class=\"fail-count\">$failed failed</span>")
            if (skipped > 0) appendLine("<span class=\"skip-count\">$skipped skipped</span>")
            appendLine("</div>")

            for ((category, specs) in categoryGroups.entries.sortedBy { it.key }) {
                appendLine("<section class=\"category\">")
                appendLine("<h2 class=\"category-header\">${escapeHtml(category)}</h2>")
                for ((specClass, specEntries) in specs) {
                    renderSpec(specClass, specEntries)
                }
                appendLine("</section>")
            }

            appendLine("</div>")
            appendLine("</body>")
            appendLine("</html>")
        }
    }

    private fun StringBuilder.renderSpec(specClass: KClass<out Spec>, specEntries: List<TestEntry>) {
        val specName = specClass.simpleName ?: "Unknown"
        val leafTests = specEntries.filter { it.testCase.type == TestType.Test }
        val allSkipped = specEntries.isNotEmpty() && specEntries.all { it.result is TestResult.Ignored }
        val allPassed = !allSkipped && leafTests.all { it.result is TestResult.Success }
        val statusClass = when {
            allSkipped -> "skip"
            allPassed -> "pass"
            else -> "fail"
        }

        appendLine("<div class=\"spec\">")
        appendLine("<h3 class=\"$statusClass\">$specName</h3>")

        // Build tree from entries
        val roots = buildTree(specEntries)
        for (node in roots) {
            renderNode(node)
        }

        appendLine("</div>")
    }

    private data class TreeNode(
        val entry: TestEntry,
        val children: MutableList<TreeNode> = mutableListOf(),
    )

    private fun buildTree(specEntries: List<TestEntry>): List<TreeNode> {
        // Map descriptor path to TreeNode
        val nodeMap = linkedMapOf<String, TreeNode>()
        for (entry in specEntries) {
            val path = entry.testCase.descriptor.path().value
            nodeMap[path] = TreeNode(entry)
        }

        // Link parent-child
        val roots = mutableListOf<TreeNode>()
        for ((path, node) in nodeMap) {
            val parent = node.entry.testCase.parent
            if (parent != null) {
                val parentPath = parent.descriptor.path().value
                val parentNode = nodeMap[parentPath]
                if (parentNode != null) {
                    parentNode.children.add(node)
                    continue
                }
            }
            roots.add(node)
        }
        return roots
    }

    private fun StringBuilder.renderNode(node: TreeNode) {
        val testCase = node.entry.testCase
        val result = node.entry.result
        val isLeaf = testCase.type == TestType.Test
        val description = testCase.name.testName
        val keyword = testCase.name.prefix?.trim()?.trimEnd(':')?.trim() ?: ""
        val keywordLower = keyword.lowercase()

        // Skipped container (e.g., xGiven) with no children
        if (!isLeaf && node.children.isEmpty() && result is TestResult.Ignored) {
            appendLine("<div class=\"test-leaf skip\">")
            appendLine("<span class=\"icon\">\u25CB</span>")
            if (keyword.isNotEmpty()) {
                appendLine("<span class=\"keyword keyword-$keywordLower\">$keyword</span>")
            }
            appendLine("${escapeHtml(description)} <em>(skipped)</em>")
            appendLine("</div>")
            return
        }

        if (isLeaf) {
            val (icon, statusClass) = when (result) {
                is TestResult.Success -> "\u2713" to "pass"
                is TestResult.Failure -> "\u2717" to "fail"
                is TestResult.Error -> "\u2717" to "fail"
                is TestResult.Ignored -> "\u25CB" to "skip"
            }
            appendLine("<div class=\"test-leaf $statusClass\">")
            appendLine("<span class=\"icon\">$icon</span>")
            if (keyword.isNotEmpty()) {
                appendLine("<span class=\"keyword keyword-$keywordLower\">$keyword</span>")
            }
            appendLine(escapeHtml(description))
            if (result is TestResult.Failure) {
                appendLine("<pre class=\"error\">${escapeHtml(result.errorOrNull?.message ?: "")}</pre>")
            }
            if (result is TestResult.Error) {
                appendLine("<pre class=\"error\">${escapeHtml(result.errorOrNull?.message ?: "")}</pre>")
            }
            appendLine("</div>")
        } else {
            appendLine("<details open>")
            append("<summary class=\"test-container\">")
            if (keyword.isNotEmpty()) {
                append("<span class=\"keyword keyword-$keywordLower\">$keyword</span> ")
            }
            append(escapeHtml(description))
            appendLine("</summary>")
            appendLine("<div class=\"children\">")
            for (child in node.children) {
                renderNode(child)
            }
            appendLine("</div>")
            appendLine("</details>")
        }
    }

    private fun escapeHtml(text: String): String {
        return text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    }

    companion object {
        private val CSS = """
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #212529; line-height: 1.6; }
            .container { max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
            h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
            .timestamp { color: #6c757d; font-size: 0.85rem; margin-bottom: 1rem; }
            .summary { margin-bottom: 1.5rem; font-size: 0.9rem; }
            .summary span { margin-right: 1rem; padding: 0.2rem 0.6rem; border-radius: 4px; }
            .total { background: #e9ecef; }
            .pass-count { background: #d4edda; color: #155724; }
            .fail-count { background: #f8d7da; color: #721c24; }
            .skip-count { background: #fff3cd; color: #856404; }
            .category { margin-bottom: 2rem; }
            .category-header { font-size: 1.2rem; color: #495057; margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 2px solid #adb5bd; }
            .spec { background: #fff; border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 1rem; padding: 1rem 1.25rem; }
            .spec h3 { font-size: 1rem; margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 1px solid #eee; }
            .spec h3.pass { color: #155724; }
            .spec h3.fail { color: #721c24; }
            .spec h3.skip { color: #856404; }
            details { margin-left: 1rem; }
            summary.test-container { cursor: pointer; font-weight: 500; padding: 0.2rem 0; color: #495057; }
            summary.test-container:hover { color: #212529; }
            .children { margin-left: 0.5rem; border-left: 2px solid #e9ecef; padding-left: 0.75rem; }
            .test-leaf { padding: 0.15rem 0; margin-left: 1rem; }
            .test-leaf.pass { color: #155724; }
            .test-leaf.fail { color: #721c24; }
            .test-leaf.skip { color: #856404; }
            .icon { font-weight: bold; margin-right: 0.25rem; }
            .keyword { display: inline-block; font-weight: 700; font-size: 0.8rem; padding: 0.05rem 0.4rem; border-radius: 3px; margin-right: 0.3rem; text-transform: uppercase; letter-spacing: 0.03em; }
            .keyword-given { background: #cce5ff; color: #004085; }
            .keyword-when { background: #d4edda; color: #155724; }
            .keyword-then { background: #fff3cd; color: #856404; }
            .keyword-and { background: #e2e3e5; color: #383d41; }
            .error { margin: 0.25rem 0 0.5rem 1.5rem; padding: 0.5rem; background: #fff5f5; border: 1px solid #f8d7da; border-radius: 4px; font-size: 0.8rem; color: #721c24; white-space: pre-wrap; word-break: break-word; }
        """.trimIndent()
    }
}
