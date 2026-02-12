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

	public func issuePendingDocuments(docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {

		if docTypeIdentifiers.isEmpty { return [] }
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		guard let authorizationServer = metaData.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}

		let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()

		// Build credential configurations for each docTypeIdentifier
		var credentialConfigurations: [CredentialConfiguration] = []
		var configurationIdentifiers: [CredentialConfigurationIdentifier] = []
		for docTypeIdentifier in docTypeIdentifiers {
			let configuration = try getCredentialConfiguration(
				credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""),
				issuerDisplay: metaData.display,
				credentialsSupported: metaData.credentialsSupported,
				identifier: docTypeIdentifier.configurationIdentifier,
				docType: docTypeIdentifier.docType,
				vct: docTypeIdentifier.vct,
				batchCredentialIssuance: metaData.batchCredentialIssuance,
				dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name),
				clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)
			)
			credentialConfigurations.append(configuration)
			configurationIdentifiers.append(configuration.configurationIdentifier)
		}

		// Create a credential offer with all configurations
		let offer = try CredentialOffer(
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			credentialIssuerMetadata: metaData,
			credentialConfigurationIdentifiers: configurationIdentifiers,
			grants: nil,
			authorizationServerMetadata: authorizationServerMetadata
		)
		// Cache the offer with a generated UUID
		let offerUri = UUID().uuidString
		Self.credentialOfferCache[offerUri] = offer
		// Build OfferedDocModel array from configurations
		let docTypes: [OfferedDocModel] = credentialConfigurations.map { config in
			OfferedDocModel(
				credentialConfigurationIdentifier: config.configurationIdentifier.value,
				docType: config.docType,
				vct: config.vct,
				scope: config.scope ?? "",
				identifier: config.configurationIdentifier.value,
				displayName: config.display.getName(uiCulture) ?? config.docType ?? config.vct ?? config.scope ?? "",
				algValuesSupported: config.credentialSigningAlgValuesSupported,
				claims: config.claims,
				credentialOptions: credentialOptions ?? config.defaultCredentialOptions,
				keyOptions: keyOptions
			)
		}

		// Delegate to issuePendingDocumentsByOfferUrl
		return try await issuePendingDocumentsByOfferUrl(offerUri: offerUri, docTypeModels: docTypes, txCodeValue: nil, promptMessage: promptMessage)
	}

	public func issuePendingDocumentsByOfferUrl(offerUri: String, docTypeModels: [OfferedDocModel], txCodeValue: String? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		if docTypeModels.isEmpty { return [] }
		guard let offer = Self.credentialOfferCache[offerUri] else {
			throw PresentationSession.makeError(str: "Offer URI not resolved: \(offerUri)")
		}

		let credentialInfos = docTypeModels.compactMap { try? getCredentialConfiguration(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.docType, vct: $0.vct, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance, dpopSigningAlgValuesSupported: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)) }
		guard credentialInfos.count > 0, credentialInfos.count == docTypeModels.count else {
			throw PresentationSession.makeError(str: "Missing Credential identifiers - expected: \(docTypeModels.count), found: \(credentialInfos.count)")
		}

		var openId4VCIServices = [OpenId4VCIService]()
		for (i, docTypeModel) in docTypeModels.enumerated() {
			guard let docTypeIdentifier = docTypeModel.docTypeIdentifier else { continue }
			let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: docTypeModel.credentialOptions, offer: offer)
			let svc = try OpenId4VCIService(uiCulture: uiCulture,  config: config, networking: networking, storage: storage, storageService: storageService)
			try await svc.prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: i > 0 ? nil : docTypeModels.map(\.displayName).joined(separator: ", "), credentialOptions: usedCredentialOptions, keyOptions: docTypeModel.keyOptions, disablePrompt: i > 0, promptMessage: promptMessage)
			openId4VCIServices.append(svc)
		}
		let issuer = try await getIssuer(offer: offer)
		let authorizedOutcome = try await authorizePARWithAuthCodeUseCase(issuer: issuer, offer: offer)

		if case .presentation_request(let url) = authorizedOutcome, let authRequested {
			logger.info("Dynamic issuance request with url: \(url)")
			let uuid = UUID().uuidString
			Self.credentialOfferCache[uuid] = offer

			let documents = try await withThrowingTaskGroup(of: WalletStorage.Document.self) { group in
				for (i, openId4VCIService) in openId4VCIServices.enumerated() {
					group.addTask {
						let outcome = IssuanceOutcome.pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: credentialInfos[i], metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod ))

						return try await self.finalizeIssuing(issueOutcome: outcome, docType: docTypeModels[i].docTypeOrVct, format: credentialInfos[i].format, issueReq: openId4VCIService.issueReq)
					}
				}
				var result =  [WalletStorage.Document]()
				for try await doc in group { result.append(doc) }
				return result
			}
			return documents
		}
		throw PresentationSession.makeError(str: "Unable to generate pending documents")
	}

	func issuePAR(_ docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document? {
		let usedKeyOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: usedKeyOptions, keyOptions: keyOptions, disablePrompt: false, promptMessage: promptMessage)
		let data = try await issueByPARType(docTypeIdentifier, promptMessage: promptMessage)
		if let outcome = data.0 {
			return try await finalizeIssuing(issueOutcome: outcome, docType: docTypeIdentifier.docType, format: data.1, issueReq: issueReq)
		}
		return nil
	}
	
//	func issuePAR(_ docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document? {
//
////		let offerUri = UUID().uuidString
////		Self.credentialOfferCache[offerUri] = offer
//
//		var openId4VCIServices = [OpenId4VCIService]()
//		for (i, docTypeIdentifier) in docTypeIdentifiers.enumerated() {
////			guard let docTypeIdentifier = docTypeModel.docTypeIdentifier else { continue }
//			let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
//			let svc = try OpenId4VCIService(uiCulture: uiCulture,  config: config, networking: networking, storage: storage, storageService: storageService)
//			let displayName = config.display.getName(uiCulture) ?? config.docType ?? config.vct ?? config.scope ?? ""
//			try await svc.prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: i > 0 ? nil : displayName, credentialOptions: usedCredentialOptions, keyOptions: keyOptions, disablePrompt: i > 0, promptMessage: promptMessage)
//		}
////		let usedKeyOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
////		try await prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: usedKeyOptions, keyOptions: keyOptions, disablePrompt: false, promptMessage: promptMessage)
//		let data = try await issueByPARType(docTypeIdentifier, promptMessage: promptMessage)
//		if let outcome = data.0 {
//			return try await finalizeIssuing(issueOutcome: outcome, docType: docTypeIdentifier.docType, format: data.1, issueReq: issueReq)
//		}
//		return nil
//	}

	private func issueByPARType(_ docTypeIdentifier: DocTypeIdentifier, promptMessage: String? = nil) async throws -> (IssuanceOutcome?, DocDataFormat) {
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		if let authorizationServer = metaData.authorizationServers?.first {
			let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: networking), oauthFetcher: Fetcher(session: networking)).resolve(url: authorizationServer)
			let authorizationServerMetadata = try authServerMetadata.get()
			let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance, dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name))
			let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())

			// Authorize with auth code flow
			let issuer = try await getIssuer(offer: offer, nonce: nil)
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

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, authorizationCode: String, nonce: String?) async throws -> WalletStorage.Document {
		guard pendingDoc.status == .pending, let docTypeIdentifier = pendingDoc.docTypeIdentifier else { throw PresentationSession.makeError(str: "Invalid document status for pending issuance: \(pendingDoc.status)")}
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(id: pendingDoc.id, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: usedCredentialOptions, keyOptions: keyOptions, disablePrompt: true, promptMessage: nil)
		let outcome = try await resumePendingIssuance(pendingDoc: pendingDoc, authorizationCode: authorizationCode, nonce: nonce)
		if case .pending(_) = outcome { return pendingDoc }
		let res = try await finalizeIssuing(issueOutcome: outcome, docType: pendingDoc.docType, format: pendingDoc.docDataFormat, issueReq: issueReq)
		return res
	}

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, authorizationCode: String, nonce: String?) async throws -> WalletStorage.Document {
		guard pendingDoc.status == .pending, let docTypeIdentifier = pendingDoc.docTypeIdentifier else { throw PresentationSession.makeError(str: "Invalid document status for pending issuance: \(pendingDoc.status)")}
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(id: pendingDoc.id, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: usedCredentialOptions, keyOptions: keyOptions, disablePrompt: true, promptMessage: nil)
		let outcome = try await resumePendingIssuance(pendingDoc: pendingDoc, authorizationCode: authorizationCode, nonce: nonce)
		if case .pending(_) = outcome { return pendingDoc }
		let res = try await finalizeIssuing(issueOutcome: outcome, docType: pendingDoc.docType, format: pendingDoc.docDataFormat, issueReq: issueReq)
		return res
	}

	private func resumePendingIssuance(pendingDoc: WalletStorage.Document, authorizationCode: String, nonce: String?) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else { throw WalletError(description: "Unknown pending reason: \(model.pendingReason)") }

		if Self.credentialOfferCache[model.metadataKey] == nil {
			if let cachedOffer = Self.credentialOfferCache.values.first {
				Self.credentialOfferCache[model.metadataKey] = cachedOffer
			}
		}
		guard let offer = Self.credentialOfferCache[model.metadataKey] else { throw WalletError(description: "Pending issuance cannot be completed") }
		let issuer = try await getIssuer(offer: offer, nonce: nonce)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")

		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)

		let authorized = try await issuer.authorizeWithAuthorizationCode(request: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil)), grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil))).get()

		let (bindingKeys, publicKeys) = try await initSecurityKeys(model.configuration)

		let res = try await Self.submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys, publicKeys: publicKeys, logger: logger)
		return res
	}

	//MARK: remove nonce: nil to enable key attestation
	private func getIssuer(offer: CredentialOffer, nonce: String?) async throws -> Issuer {
		var dpopConstructor: DPoPConstructorType? = nil
		if config.useDpopIfSupported {
			dpopConstructor = try await config.makeDPoPConstructor(keyId: issueReq.dpopKeyId, algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported, nonce: nil)
		}
		let vciConfig = try await config.toOpenId4VCIConfigWithPrivateKey(credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString, clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported)
		return try Issuer(
			authorizationServerMetadata: offer.authorizationServerMetadata,
			issuerMetadata: offer.credentialIssuerMetadata,
			config: vciConfig,
			parPoster: Poster(session: networking),
			tokenPoster: Poster(session: networking),
			requesterPoster: Poster(session: networking),
			deferredRequesterPoster: Poster(session: networking),
			notificationPoster: Poster(session: networking),
			noncePoster: Poster(session: networking),
			dpopConstructor: dpopConstructor
		)
	}

	func getCredentialsWithRefreshToken(docTypeIdentifier: DocTypeIdentifier, authorizedRequest: AuthorizedRequest, issuerDPopConstructorParam: IssuerDPoPConstructorParam, docId: String) async throws -> (IssuanceOutcome?, DocDataFormat?, AuthorizedRequest?) {

		let dpopConstructor = DPoPConstructor(algorithm: JWSAlgorithm(.ES256), jwk: issuerDPopConstructorParam.jwk, privateKey: .secKey(issuerDPopConstructorParam.privateKey))
		do {
			let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()

			let issuerInfo = try await fetchIssuerAndOfferWithLatestMetadata(docTypeIdentifier: docTypeIdentifier, dpopConstructor: dpopConstructor)
			if let issuer = issuerInfo.0, let offer = issuerInfo.1 {

				let result = await issuer.refresh(clientId: config.clientId, authorizedRequest: authorizedRequest)
				switch result {
				case .success(let authReq):
					let updatedAuthRequest = authReq

					if offer.credentialConfigurationIdentifiers.first != nil {
						do {
							guard let authorizationServer = metaData.authorizationServers?.first else {
								throw WalletError(description: "Invalid issuer metadata")
							}
							let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
							let authorizationServerMetadata = try authServerMetadata.get()

							let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance, dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name))

							let (bindingKeys, publicKeys) = try await initSecurityKeys(configuration)

							let issuanceOutcome = try await Self.submissionUseCase(authorizedRequest, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys, publicKeys: publicKeys, logger: logger)

							return (issuanceOutcome, configuration.format, updatedAuthRequest)
						} catch {
							throw WalletError(description: error.localizedDescription)
						}
					}
				case .failure(let error):
					throw WalletError(description: "Invalid issuer metadata: \(error)")
				}
			}
		} catch {
			throw WalletError(description: error.localizedDescription)
		}
		throw WalletError(description: "Error with refreshing credentials")
	}

	private func fetchIssuerAndOfferWithLatestMetadata(docTypeIdentifier: DocTypeIdentifier, dpopConstructor: DPoPConstructorType) async throws -> (Issuer?, CredentialOffer?) {
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()

		if let authorizationServer = metaData.authorizationServers?.first {
			let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: networking), oauthFetcher: Fetcher(session: networking)).resolve(url: authorizationServer)
			let authorizationServerMetadata = try authServerMetadata.get()
			let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance, dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name))

			let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())

			let issuer = try await getIssuer(offer: offer)

			return (issuer, offer)
		}
		throw WalletError(description: "Error with refreshing credentials")
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

public struct IssuerDPoPConstructorParam: @unchecked Sendable {
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
public struct ClientAttestation: Sendable {
	public let wia: String
	public let wiaPop: String

	public init(wia: String, wiaPop: String) {
		self.wia = wia
		self.wiaPop = wiaPop
	}
}
