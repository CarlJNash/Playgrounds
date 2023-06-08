import PlaygroundSupport
import Foundation
import CryptoKit
import CommonCrypto
import Security

func hashPassword(_ password: String) -> String? {
    guard let salt = generateSalt() else {
        return nil
    }

    let passwordData = Data(password.utf8)
    let saltData = Data(salt.utf8)
    var hashData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))

    guard CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password, passwordData.count,
            salt, saltData.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            10, // iterations
            &hashData, hashData.count) == kCCSuccess else {
        return nil
    }

    let saltString = saltData.base64EncodedString()
    let hashString = hashData.base64EncodedString()
    return "\(saltString):\(hashString)"
}

private func generateSalt() -> String? {
    let count = 32
    var bytes = [UInt8](repeating: 0, count: count)

    let result = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    guard result == errSecSuccess else {
        return nil
    }

    return Data(bytes).base64EncodedString()
}

func savePasswordToKeychain(password: String) -> Bool {
    let service = "com.example.app"
    let account = "user123"

    guard let passwordData = password.data(using: .utf8) else {
        return false
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: passwordData
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess
}

let password = "someCrappyPassword"
if let hashedPassword = hashPassword(password) {
    print(hashedPassword)
    savePasswordToKeychain(password: hashedPassword)
} else {
    print("could not hash password")
}

PlaygroundPage.current.needsIndefiniteExecution = true

