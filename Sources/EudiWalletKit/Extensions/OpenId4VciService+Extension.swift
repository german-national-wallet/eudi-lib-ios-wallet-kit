//
//  OpenId4VCIService.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 20.12.24.
//

import Foundation
@preconcurrency import OpenID4VCI
import MdocDataModel18013
import CryptorECC
import JOSESwift
import WalletStorage

extension OpenId4VCIService {

	func issuePAR(_ docTypeIdentifier: DocTypeIdentifier, promptMessage: String? = nil, dpopConstructorParam: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome?, DocDataFormat) {
		logger.log(level: .info, "Issuing document with docType or scope or identifier: \(docTypeIdentifier.value)")
		let res = try await issueByPARType(docTypeIdentifier, promptMessage: promptMessage, dpopConstructorParam: dpopConstructorParam)
		return res
	}
	
	func resumePendingIssuance(pendingDoc: WalletStorage.Document, authorizationCode: String) async throws -> (IssuanceOutcome, AuthorizedRequest?) {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else { throw WalletError(description: "Unknown pending reason: \(model.pendingReason)") }
		
		if Self.credentialOfferCache[model.metadataKey] == nil {
			if let cachedOffer = Self.credentialOfferCache.values.first {
				Self.credentialOfferCache[model.metadataKey] = cachedOffer
			}
		}
		guard let offer = Self.credentialOfferCache[model.metadataKey] else { throw WalletError(description: "Pending issuance cannot be completed") }
		let issuer = try getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")

		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)

		let authorized = try await issuer.authorizeWithAuthorizationCode(request: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil))).get()

//		let authReqParams = convertAuthorizedRequestToParam(authorizedRequest: authorized)
		
		let (bindingKeys, publicKeys) = try await initSecurityKeys(algSupported: Set(model.configuration.credentialSigningAlgValuesSupported))

//		let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, configuration: model.configuration, claimSet: nil, algSupported: Set(model.configuration.algValuesSupported))
//		Self.metadataCache.removeValue(forKey: model.metadataKey)
		let res = try await submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys, publicKeys: publicKeys)
		return (res, authorized)
	}
	
	func getCredentialsWithRefreshToken(docTypeIdentifier: DocTypeIdentifier, authorizedRequest: AuthorizedRequest, issuerDPopConstructorParam: IssuerDPoPConstructorParam, docId: String) async throws -> (IssuanceOutcome?, DocDataFormat?, AuthorizedRequest?) {

		let dpopConstructor = DPoPConstructor(algorithm: JWSAlgorithm(.ES256), jwk: issuerDPopConstructorParam.jwk, privateKey: .secKey(issuerDPopConstructorParam.privateKey))
		do {
			let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()

			let issuerInfo = try await fetchIssuerAndOfferWithLatestMetadata(docTypeIdentifier: docTypeIdentifier, dpopConstructor: dpopConstructor)
			if let issuer = issuerInfo.0, let offer = issuerInfo.1 {
				
				let result = await issuer.refresh(clientId: config.client.id, authorizedRequest: authorizedRequest)
				switch result {
				case .success(let authReq):
					let updatedAuthRequest = authReq

					if offer.credentialConfigurationIdentifiers.first != nil {
						do {
							let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance)

							let (bindingKeys, publicKeys) = try await initSecurityKeys(algSupported: Set(configuration.credentialSigningAlgValuesSupported))

							let issuanceOutcome = try await submissionUseCase(authorizedRequest, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys, publicKeys: publicKeys)

							return (issuanceOutcome, configuration.format, updatedAuthRequest)
						} catch {
							throw WalletError(description: "Invalid issuer metadata")
						}
					}
				case .failure(let error):
					throw WalletError(description: "Invalid issuer metadata")
				}
			}
		} catch {
			throw WalletError(description: "Invalid issuer metadata")
		}
		return (nil, nil, nil)
	}

	private func issueByPARType(_ docTypeIdentifier: DocTypeIdentifier, promptMessage: String? = nil, dpopConstructorParam: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome?, DocDataFormat) {
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		if let authorizationServer = metaData.authorizationServers?.first {
			let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: networking), oauthFetcher: Fetcher(session: networking)).resolve(url: authorizationServer)
			let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance)
			let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())

			// Authorize with auth code flow
			let issuer = try getIssuer(offer: offer)
			let authorizedOutcome = try await authorizePARWithAuthCodeUseCase(issuer: issuer, offer: offer)
			if case .presentation_request(let url) = authorizedOutcome, let authRequested {
				logger.info("Dynamic issuance request with url: \(url)")
				let uuid = UUID().uuidString
				Self.credentialOfferCache[uuid] = offer
				let outcome = IssuanceOutcome.pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod ))
				return (outcome, configuration.format)
			}
			return (nil, configuration.format)
		} else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}
	}

	private func fetchIssuerAndOfferWithLatestMetadata(docTypeIdentifier: DocTypeIdentifier, dpopConstructor: DPoPConstructorType) async throws -> (Issuer?, CredentialOffer?) {
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()

		if let authorizationServer = metaData.authorizationServers?.first {
			let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: networking), oauthFetcher: Fetcher(session: networking)).resolve(url: authorizationServer)

			let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance)

			let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())

			let issuer = try getIssuer(offer: offer)

			return (issuer, offer)
		}
		return (nil, nil)
	}

	private func authorizePARWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws ->  AuthorizeRequestOutcome? {
		let pushedAuthorizationRequestEndpoint = if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else { "" }
		if config.usePAR && pushedAuthorizationRequestEndpoint.isEmpty { logger.info("PAR not supported, Pushed Authorization Request Endpoint is nil") }
		logger.info("--> [AUTHORIZATION] Placing Request to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
		let parPlaced = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)

		if case let .success(request) = parPlaced,
		   case let .prepared(authRequested) = request {
			self.authRequested = authRequested
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(pushedAuthorizationRequestEndpoint)")

			return .presentation_request(authRequested.authorizationCodeURL.url)
		} else if case let .failure(failure) = parPlaced {
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		throw WalletError(description: "Failed to get push authorization code request")
	}
}

public struct IssuerDPoPConstructorParam {
	let clientID: String?
	let expirationDuration: TimeInterval?
	let aud: String?
	let jti: String?
	let jwk: JWK
	let privateKey: SecKey
	
	public init(clientID: String?, expirationDuration: TimeInterval?, aud: String?, jti: String?, jwk: JWK, privateKey: SecKey) {
		self.clientID = clientID
		self.expirationDuration = expirationDuration
		self.aud = aud
		self.jti = jti
		self.jwk = jwk
		self.privateKey = privateKey
	}
}

public struct AuthorizedRequestParams: Sendable {
	public let accessToken: String?
	public let refreshToken: String?
	public let cNonce: String?
	public let timeStamp: TimeInterval
	public let dPopNonce: Nonce?
	
	public init(accessToken: String, refreshToken: String?, cNonce: String?, timeStamp: TimeInterval, dPopNonce: Nonce?) {
		self.accessToken = accessToken
		self.refreshToken = refreshToken
		self.cNonce = cNonce
		self.timeStamp = timeStamp
		self.dPopNonce = dPopNonce
	}
}
