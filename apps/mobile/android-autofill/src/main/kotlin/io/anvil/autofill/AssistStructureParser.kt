package io.anvil.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

data class ParsedAssistStructure(
    val packageName: String,
    val webDomain: String?,
    val usernameId: AutofillId?,
    val passwordId: AutofillId?,
    val otpId: AutofillId?,
)

/** Traverses Android `AssistStructure` nodes to isolate origin domain, package ID, and target field IDs. */
object AssistStructureParser {
    fun parse(structure: AssistStructure): ParsedAssistStructure {
        val pkg = structure.activityComponent?.packageName.orEmpty()
        var webDomain: String? = null
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var otpId: AutofillId? = null

        fun visitNode(node: AssistStructure.ViewNode) {
            if (webDomain == null && !node.webDomain.isNullOrBlank()) {
                val scheme = node.webScheme?.takeIf { it.isNotBlank() } ?: "https"
                webDomain = "$scheme://${node.webDomain}"
            }

            val autofillId = node.autofillId
            if (autofillId != null) {
                val hints = node.autofillHints?.map { it.lowercase() }.orEmpty()
                val inputType = node.inputType
                val isPasswordInput =
                    (inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD) != 0 ||
                        (inputType and InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) != 0

                when {
                    hints.contains(View.AUTOFILL_HINT_PASSWORD) || isPasswordInput -> {
                        if (passwordId == null) passwordId = autofillId
                    }
                    hints.any { it.contains("otp") || it == "smsotpcode" || it == "2facode" } -> {
                        if (otpId == null) otpId = autofillId
                    }
                    hints.contains(View.AUTOFILL_HINT_USERNAME) ||
                        hints.contains(View.AUTOFILL_HINT_EMAIL_ADDRESS) -> {
                        if (usernameId == null) usernameId = autofillId
                    }
                }
            }

            for (i in 0 until node.childCount) {
                visitNode(node.getChildAt(i))
            }
        }

        for (i in 0 until structure.windowCount) {
            structure.getWindowAt(i).rootViewNode?.let(::visitNode)
        }

        return ParsedAssistStructure(
            packageName = pkg,
            webDomain = webDomain,
            usernameId = usernameId,
            passwordId = passwordId,
            otpId = otpId,
        )
    }
}
