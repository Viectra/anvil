import AuthenticationServices
import LocalAuthentication
import UIKit

/// Low-memory iOS AutoFill extension unlocking the shared App Group encrypted cache via Face ID / Touch ID.
final class AnvilCredentialProviderViewController: ASCredentialProviderViewController {
    private let keychain = AppGroupKeychain()
    private var pendingServiceIdentifiers: [ASCredentialServiceIdentifier] = []

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        self.pendingServiceIdentifiers = serviceIdentifiers
        super.prepareCredentialList(for: serviceIdentifiers)
    }

    override func provideCredentialWithoutUserInteraction(
        for credentialIdentity: ASPasswordCredentialIdentity
    ) {
        let context = LAContext()
        var authError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else {
            extensionContext.cancelRequest(withError: NSError(
                domain: ASExtensionErrorDomain,
                code: ASExtensionError.userInteractionRequired.rawValue
            ))
            return
        }
        authenticateAndComplete(
            user: credentialIdentity.user,
            recordIdentifier: credentialIdentity.recordIdentifier,
            serviceIdentifier: credentialIdentity.serviceIdentifier,
            laContext: context
        )
    }

    override func prepareInterfaceToProvideCredential(
        for credentialIdentity: ASPasswordCredentialIdentity
    ) {
        let context = LAContext()
        context.localizedReason = "Déverrouiller votre fiche Anvil"
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: context.localizedReason) {
            [weak self] success, error in
            DispatchQueue.main.async {
                guard let self else { return }
                if !success {
                    let cancelErr = error ?? NSError(
                        domain: ASExtensionErrorDomain,
                        code: ASExtensionError.userCanceled.rawValue
                    )
                    self.extensionContext.cancelRequest(withError: cancelErr)
                    return
                }
                self.authenticateAndComplete(
                    user: credentialIdentity.user,
                    recordIdentifier: credentialIdentity.recordIdentifier,
                    serviceIdentifier: credentialIdentity.serviceIdentifier,
                    laContext: context
                )
            }
        }
    }

    private func authenticateAndComplete(
        user: String,
        recordIdentifier: String?,
        serviceIdentifier: ASCredentialServiceIdentifier,
        laContext: LAContext
    ) {
        guard let itemId = recordIdentifier,
              let cacheUrl = keychain.sharedCacheUrl(),
              let userId = UserDefaults(suiteName: "group.io.anvil.vault")?.string(forKey: "active_user_id")
        else {
            extensionContext.cancelRequest(withError: NSError(
                domain: ASExtensionErrorDomain,
                code: ASExtensionError.credentialIdentityNotFound.rawValue
            ))
            return
        }

        do {
            var vaultKeyData = try keychain.unsealVaultKey(userId: userId, context: laContext)
            defer { vaultKeyData.resetBytes(in: 0..<vaultKeyData.count) }

            let domains = (pendingServiceIdentifiers + [serviceIdentifier]).map(\.identifier)
            let resolved = try resolveMobileCredentialViaFfi(
                cachePath: cacheUrl.path,
                itemId: itemId,
                associatedDomains: domains,
                vaultKey: vaultKeyData
            )

            let credential = ASPasswordCredential(user: resolved.username, password: resolved.password)
            extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
        } catch {
            extensionContext.cancelRequest(withError: error)
        }
    }

    private func resolveMobileCredentialViaFfi(
        cachePath: String,
        itemId: String,
        associatedDomains: [String],
        vaultKey: Data
    ) throws -> (username: String, password: String) {
        // Bound to AnvilMobile FFI (`LowMemoryAutofillUnlocker` + `MobileAutofillEngine`) at Xcode link stage.
        throw NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.credentialIdentityNotFound.rawValue,
            userInfo: [
                NSLocalizedDescriptionKey: "Link AnvilMobile XCFramework for \(cachePath) (\(itemId))",
                "associated_domains_count": associatedDomains.count,
                "key_len": vaultKey.count,
            ]
        )
    }
}
