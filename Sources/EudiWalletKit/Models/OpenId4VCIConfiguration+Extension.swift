//
//  OpenId4VCIConfiguration+Extension.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 24.09.25.
//
import Foundation
import JOSESwift
import OpenID4VCI
import MdocSecurity18013

extension OpenId4VCIConfiguration {
	static func makeDPoPConstructor(algorithms: [JWSAlgorithm]?, dPopConstructorParam: IssuerDPoPConstructorParam) throws -> DPoPConstructorType? {
		guard let algorithms = algorithms, !algorithms.isEmpty else { return nil }
		let setCommonJwsAlgorithmNames = Array(Set(algorithms.map(\.name)).intersection(Self.supportedDPoPAlgorithms.map(\.name))).sorted()
		guard let algName = setCommonJwsAlgorithmNames.first else {
			throw WalletError(description: "No supported DPoP algorithm found in the provided algorithms \(algorithms.map(\.name)). Supported algorithms are: \(Self.supportedDPoPAlgorithms.map(\.name))")
		}
		let alg = JWSAlgorithm(name: algName)
		logger.info("Signing algorithm for DPoP constructor to be used is: \(alg.name)")
		
		let privateKeyProxy: SigningKeyProxy = .secKey(dPopConstructorParam.privateKey)
		return DPoPConstructor(algorithm: alg, jwk: dPopConstructorParam.jwk, privateKey: privateKeyProxy)
	}
}