import Foundation
import LocalAuthentication
import Security

/// App Group Keychain bridge storing ONLY the 32-byte `VaultKey` behind Secure Enclave biometry.
/// Enables instant unlock inside the 30-50 MB iOS Credential Provider memory cap without Argon2id.
final class AppGroupKeychain {
    static let accessGroup = "io.anvil.vault.shared"
    static let accountTag = "anvil.vault_key.v1"

    func sealVaultKey(_ vaultKey: Data, userId: String) throws {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet],
            &error
        ) else {
            throw error?.takeRetainedValue() ?? NSError(domain: "io.anvil.autofill", code: -1)
        }

        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: Self.accessGroup,
            kSecAttrService as String: Self.accountTag,
            kSecAttrAccount as String: userId,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: Self.accessGroup,
            kSecAttrService as String: Self.accountTag,
            kSecAttrAccount as String: userId,
            kSecAttrAccessControl as String: accessControl,
            kSecValueData as String: vaultKey,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    func unsealVaultKey(userId: String, context: LAContext) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: Self.accessGroup,
            kSecAttrService as String: Self.accountTag,
            kSecAttrAccount as String: userId,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let keyData = item as? Data else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return keyData
    }

    func sharedCacheUrl() -> URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.io.anvil.vault")?
            .appendingPathComponent("mobile_cache.db")
    }
}
