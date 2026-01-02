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
	func makeDPoPConstructor(keyId dpopKeyId: String?, algorithms: [JWSAlgorithm]?, nonce: String?) async throws -> DPoPConstructorType? {
		guard let algorithms = algorithms, !algorithms.isEmpty else { return nil }
		let privateKeyProxy: SigningKeyProxy
		let publicKey: SecKey
		let jwsAlgorithm: JWSAlgorithm
		let jwk: any JWK
		let keyId = dpopKeyId ?? UUID().uuidString
		if var dpopKeyOptions {
			// If dpopKeyOptions is specified, use it to determine key generation parameters
			let secureArea = SecureAreaRegistry.shared.get(name: dpopKeyOptions.secureAreaName)
			let ecCurve = dpopKeyOptions.curve
			let ecAlgorithm = await secureArea.defaultSigningAlgorithm(ecCurve: dpopKeyOptions.curve)
			guard let jwsAlg = ecCurve.jwsAlgorithm, algorithms.map(\.name).contains(jwsAlg.name) else {
				throw WalletError(description: "Specified algorithm \(ecCurve.SECGName) not supported by server supported algorithms \(algorithms.map(\.name))") }
			jwsAlgorithm = jwsAlg
			let publicCoseKey: CoseKey = if let dpopKeyId, !dpopKeyId.hasSuffix("_dpop"), let keyInfo = try? await secureArea.getKeyBatchInfo(id: dpopKeyId), dpopKeyOptions.secureAreaName == keyInfo.secureAreaName, dpopKeyOptions.curve == ecCurve, keyInfo.usedCounts.count == 1, let pck = try? await secureArea.getPublicKey(id: dpopKeyId, index: 0, curve: ecCurve) { pck } else {
				(try await secureArea.createKeyBatch(id: keyId, credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1), keyOptions: dpopKeyOptions)).first! }
//			let unlockData = try await secureArea.unlockKey(id: keyId)
			let signer = try SecureAreaSigner(secureArea: secureArea, id: keyId, index: 0, ecAlgorithm: ecAlgorithm, unlockData: nil)
			privateKeyProxy = .custom(signer)
			publicKey = try publicCoseKey.toSecKey()
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
			let privateKey: SecKey = if let dpopKeyId, !dpopKeyId.hasSuffix("_dpop"), let pk = SecKey.getExistingKey(type: type, keyId: dpopKeyId) { pk } else { try SecKey.createRandomKey(type: type, bits: bits, keyId: dpopKeyId) }
			privateKeyProxy = .secKey(privateKey)
			publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		}
		if jwsAlgorithm.name.starts(with: "RS") {
			jwk = try RSAPublicKey(publicKey: publicKey, additionalParameters: ["alg": jwsAlgorithm.name, "use": "sig", "kid": keyId])
		} else {
			jwk = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": jwsAlgorithm.name, "use": "sig", "kid": keyId])
		}
		return DPoPConstructor(algorithm: jwsAlgorithm, jwk: jwk, privateKey: privateKeyProxy)
	}

	//MARK: Duplicate function(toOpenId4VCIConfig) to allow passing of private key for client attestation jwt creation
	func toOpenId4VCIConfigWithPrivateKey(credentialIssuerId: String, clientAttestationPopSigningAlgValuesSupported: [JWSAlgorithm]?) async throws -> OpenId4VCIConfig {
		let client: Client = if let keyAttestationsConfig, clientAttestationPopSigningAlgValuesSupported != nil { try await makeAttestationClientWithPrivateKey(config: keyAttestationsConfig, credentialIssuerId: credentialIssuerId, algorithms: clientAttestationPopSigningAlgValuesSupported) } else { .public(id: clientId) }
		let clientAttestationPoPBuilder: ClientAttestationPoPBuilder? = if keyAttestationsConfig != nil { DefaultClientAttestationPoPBuilder() } else { nil}
		return OpenId4VCIConfig(client: client, authFlowRedirectionURI: authFlowRedirectionURI, authorizeIssuanceConfig: authorizeIssuanceConfig, usePAR: usePAR, clientAttestationPoPBuilder: clientAttestationPoPBuilder, useDpopIfSupported: useDpopIfSupported)
	}

	//MARK: Duplicate function(makeAttestationClient) to allow passing of private key for client attestation jwt creation
	private func makeAttestationClientWithPrivateKey(config: KeyAttestationConfig, credentialIssuerId: String, algorithms: [JWSAlgorithm]?) async throws -> Client {
		let keyId = generatePopKeyId(credentialIssuerId: credentialIssuerId)
		guard let dpopConstructor = try await makeDPoPConstructor(keyId: keyId, algorithms: algorithms) else {	 throw WalletError(description: "Failed to create DPoP constructor for client attestation") }

		guard case .secKey(let privateKey) = dpopConstructor.privateKey else {
			throw WalletError(description: "Failed to get the private key for the custom signer")
		}
		let attestation = try await config.walletAttestationsProvider.getWalletAttestation(key: dpopConstructor.jwk, privateKey: privateKey)
		guard let signatureAlgorithm = SignatureAlgorithm(rawValue: dpopConstructor.algorithm.name) else {
			throw WalletError(description: "Unsupported DPoP algorithm: \(dpopConstructor.algorithm.name) for client attestation")
		}
		let popJwtSpec = try ClientAttestationPoPJWTSpec(signingAlgorithm: signatureAlgorithm, duration: config.popKeyDuration ?? 300.0, typ: "oauth-client-attestation-pop+jwt", signingKey: dpopConstructor.privateKey)
		let client: Client = .attested(attestationJWT: try .init(jws: .init(compactSerialization: attestation)), popJwtSpec: popJwtSpec)
		return client
	}
}
