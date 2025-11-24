//
//  OpenId4VciConfiguration+Extension.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 10.11.25.
//
import Foundation
import JOSESwift
import OpenID4VCI
import MdocDataModel18013
import MdocSecurity18013

extension OpenId4VciConfiguration {
	func makeDPoPConstructor(keyId dpopKeyId: String, algorithms: [JWSAlgorithm]?, nonce: String?) async throws -> DPoPConstructorType? {
		guard let algorithms = algorithms, !algorithms.isEmpty else { return nil }
		guard useDpopIfSupported else { return nil }
		let privateKeyProxy: SigningKeyProxy
		let publicKey: SecKey
		let jwsAlgorithm: JWSAlgorithm
		var keyAttestation: String? = nil
		if var dpopKeyOptions {
			// If dpopKeyOptions is specified, use it to determine key generation parameters
			let secureArea = SecureAreaRegistry.shared.get(name: dpopKeyOptions.secureAreaName)
			let ecCurve = dpopKeyOptions.curve
			guard let jwsAlg = ecCurve.jwsAlgorithm, algorithms.map(\.name).contains(jwsAlg.name) else {
				throw WalletError(description: "Specified algorithm \(ecCurve.SECGName) not supported by server supported algorithms \(algorithms.map(\.name))") }
			jwsAlgorithm = jwsAlg
			if let nonce {
				dpopKeyOptions.additionalOptions = nonce.data(using: .utf8)
			}
			let publicCoseKey = (try await secureArea.createKeyBatch(id: dpopKeyId, credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1), keyOptions: dpopKeyOptions)).first!
//			let unlockData = try await secureArea.unlockKey(id: dpopKeyId)
			let ecAlgorithm = await secureArea.defaultSigningAlgorithm(ecCurve: dpopKeyOptions.curve)
			let signer = try SecureAreaSigner(secureArea: secureArea, id: dpopKeyId, index: 0, ecAlgorithm: ecAlgorithm, unlockData: nil)
			privateKeyProxy = .custom(signer)
			publicKey = try publicCoseKey.toSecKey()
//			await print("getKeyBatchInfo:",try secureArea.getKeyBatchInfo(id: dpopKeyId))
//			let keyBatchInfo = try await secureArea.getKeyBatchInfo(id: dpopKeyId)
//			keyAttestation = keyBatchInfo.attestation?.attestation?.first
		} else {
			let setCommonJwsAlgorithmNames = Array(Set(algorithms.map(\.name)).intersection(Self.supportedDPoPAlgorithms.map(\.name))).sorted()
			guard let algName = setCommonJwsAlgorithmNames.first else {
				throw WalletError(description: "No wallet supported DPoP algorithm found in the server supported algorithms \(algorithms.map(\.name)). Wallet supported algorithms are: \(Self.supportedDPoPAlgorithms.map(\.name))")
			}
			jwsAlgorithm = JWSAlgorithm(name: algName)
			logger.info("Signing algorithm for DPoP constructor to be used is: \(jwsAlgorithm.name)")
			// EC supported bit sizes are 256, 384, or 521. RS256 is 2048 bits.
			let bits: Int = switch jwsAlgorithm.name { case JWSAlgorithm(.ES256).name: 256; case JWSAlgorithm(.ES384).name: 384; case JWSAlgorithm(.ES512).name: 521; case JWSAlgorithm(.RS256).name: 2048; default: throw WalletError(description: "Unsupported DPoP algorithm: \(jwsAlgorithm.name)") }
			let type: SecKey.KeyType = switch jwsAlgorithm.name { case JWSAlgorithm(.RS256).name: .rsa; default: .ellipticCurve }
			let privateKey = try SecKey.createRandomKey(type: type, bits: bits)
			privateKeyProxy = .secKey(privateKey)
			publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		}
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": jwsAlgorithm.name, "use": "sig", "kid": UUID().uuidString])
		return DPoPConstructor(algorithm: jwsAlgorithm, jwk: publicKeyJWK, privateKey: privateKeyProxy, keyAttestation: keyAttestation)
	}
}
