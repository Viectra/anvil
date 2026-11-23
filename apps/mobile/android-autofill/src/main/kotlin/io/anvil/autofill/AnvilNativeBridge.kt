package io.anvil.autofill

/** JNI contract exported by `libanvil_mobile.so` (`anvil-mobile` crate). */
object AnvilNativeBridge {
    init {
        System.loadLibrary("anvil_mobile")
    }

    /** Calls `cmd_autofill_query` with JSON `AutofillCallerContext`, returning JSON `AutofillCandidate[]`. */
    external fun nativeQueryAutofill(cachePath: String, callerContextJson: String): String

    /** Calls `cmd_autofill_fill` after explicit user selection + biometric/unlock validation. */
    external fun nativeResolveFill(
        cachePath: String,
        itemId: String,
        callerContextJson: String,
        unixTimestampSeconds: Long,
    ): String
}
