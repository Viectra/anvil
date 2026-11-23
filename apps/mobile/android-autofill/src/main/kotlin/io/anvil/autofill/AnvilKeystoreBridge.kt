package io.anvil.autofill

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed Android Keystore (StrongBox when available) wrapper sealing ONLY the 32-byte `VaultKey`.
 * Never persists the Master Password.
 */
class AnvilKeystoreBridge(private val context: Context) {
    private val keyAlias = "anvil.vault.biometric.seal.v1"
    private val prefsName = "anvil_keystore_seal"

    fun prepareSealCipher(userId: String): Cipher {
        val secretKey = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    fun prepareUnsealCipher(): Cipher {
        val blob = loadSealedBlob() ?: throw IllegalStateException("No sealed VaultKey present")
        val ivLen = ByteBuffer.wrap(blob, 0, 4).int
        val iv = blob.copyOfRange(4, 4 + ivLen)
        val secretKey = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        return cipher
    }

    fun sealWithAuthenticatedCipher(cipher: Cipher, userId: String, vaultKey: ByteArray) {
        cipher.updateAAD(userId.toByteArray(Charsets.UTF_8))
        val encrypted = cipher.doFinal(vaultKey)
        val iv = cipher.iv
        val packet = ByteBuffer.allocate(4 + iv.size + encrypted.size)
            .putInt(iv.size)
            .put(iv)
            .put(encrypted)
            .array()
        context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
            .edit()
            .putString("sealed_vault_key_b64", android.util.Base64.encodeToString(packet, android.util.Base64.NO_WRAP))
            .putString("sealed_user_id", userId)
            .apply()
    }

    fun unsealWithAuthenticatedCipher(cipher: Cipher): ByteArray {
        val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        val userId = prefs.getString("sealed_user_id", null)
            ?: throw IllegalStateException("Missing bound userId")
        val packet = loadSealedBlob() ?: throw IllegalStateException("No sealed VaultKey present")
        val ivLen = ByteBuffer.wrap(packet, 0, 4).int
        val ciphertext = packet.copyOfRange(4 + ivLen, packet.size)
        cipher.updateAAD(userId.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(ciphertext)
    }

    fun cryptoObjectForPrompt(cipher: Cipher): BiometricPrompt.CryptoObject =
        BiometricPrompt.CryptoObject(cipher)

    private fun loadSealedBlob(): ByteArray? {
        val b64 = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
            .getString("sealed_vault_key_b64", null) ?: return null
        return android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(keyAlias, null) as? SecretKey
        if (existing != null) return existing

        val specBuilder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            generator.init(specBuilder.build())
            generator.generateKey()
        } catch (_: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                specBuilder.setIsStrongBoxBacked(false)
            }
            generator.init(specBuilder.build())
            generator.generateKey()
        }
    }
}
