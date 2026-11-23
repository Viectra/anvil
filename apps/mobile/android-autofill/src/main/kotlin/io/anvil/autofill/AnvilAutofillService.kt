package io.anvil.autofill

import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import org.json.JSONArray
import org.json.JSONObject

/** System Android `AutofillService` backed by encrypted SQLite cache and verified app/web identity. */
class AnvilAutofillService : AutofillService() {
    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val contextStructure = request.fillContexts.lastOrNull()?.structure
        if (contextStructure == null) {
            callback.onSuccess(null)
            return
        }

        val parsed = AssistStructureParser.parse(contextStructure)
        val hasTarget = parsed.usernameId != null || parsed.passwordId != null
        if (!hasTarget) {
            callback.onSuccess(null)
            return
        }

        val callerJson = JSONObject()
            .put("platform", "android")
            .put("web_domain", parsed.webDomain ?: JSONObject.NULL)
            .put("android_package_name", parsed.packageName.ifEmpty { JSONObject.NULL })
            .put("ios_associated_domains", JSONArray())
            .toString()

        val cachePath = "${filesDir.absolutePath}/mobile_cache.db"
        val candidatesRaw = try {
            AnvilNativeBridge.nativeQueryAutofill(cachePath, callerJson)
        } catch (_: Throwable) {
            callback.onSuccess(null)
            return
        }

        val candidates = JSONArray(candidatesRaw)
        val responseBuilder = FillResponse.Builder()
        val nowUnix = System.currentTimeMillis() / 1000L

        for (i in 0 until candidates.length()) {
            val cand = candidates.getJSONObject(i)
            val itemId = cand.getString("item_id")
            val title = cand.getString("title")
            val subtitle = cand.optString("subtitle", "")

            val fillRaw = try {
                AnvilNativeBridge.nativeResolveFill(cachePath, itemId, callerJson, nowUnix)
            } catch (_: Throwable) {
                continue
            }
            val fill = JSONObject(fillRaw)

            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_2).apply {
                setTextViewText(android.R.id.text1, title)
                setTextViewText(android.R.id.text2, subtitle)
            }

            val datasetBuilder = Dataset.Builder(presentation)
            parsed.usernameId?.let { id ->
                datasetBuilder.setValue(id, AutofillValue.forText(fill.optString("username", "")))
            }
            parsed.passwordId?.let { id ->
                datasetBuilder.setValue(id, AutofillValue.forText(fill.optString("password", "")))
            }
            parsed.otpId?.let { id ->
                val otp = fill.optString("totp_code", "")
                if (otp.isNotEmpty()) {
                    datasetBuilder.setValue(id, AutofillValue.forText(otp))
                }
            }
            responseBuilder.addDataset(datasetBuilder.build())
        }

        val saveTargets = listOfNotNull(parsed.usernameId, parsed.passwordId).toTypedArray()
        if (saveTargets.isNotEmpty()) {
            responseBuilder.setSaveInfo(
                SaveInfo.Builder(
                    SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME,
                    saveTargets,
                ).build(),
            )
        }

        if (!cancellationSignal.isCanceled) {
            callback.onSuccess(responseBuilder.build())
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Persist newly captured credentials strictly inside app-controlled UI/Rust flow.
        callback.onSuccess()
    }
}
