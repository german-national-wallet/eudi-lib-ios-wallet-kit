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
		
		let bindingKeys = try await initSecurityKeys(algSupported: Set(model.configuration.credentialSigningAlgValuesSupported))

//		let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, configuration: model.configuration, claimSet: nil, algSupported: Set(model.configuration.algValuesSupported))
//		Self.metadataCache.removeValue(forKey: model.metadataKey)
		let res = try await submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys)
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

//					if let cnonce = cnonce {
//						if case let .noProofRequired(accessToken, refreshToken, credentialIdentifiers, timeStamp, dPopNonce) = authReq {
//							authRequest = .proofRequired(accessToken: accessToken, refreshToken: refreshToken, cNonce: cnonce, credentialIdentifiers: credentialIdentifiers, timeStamp: timeStamp, dPopNonce: dPopNonce)
//						}
//					}
					if offer.credentialConfigurationIdentifiers.first != nil {
						do {
//							let configuration = try getCredentialIdentifier(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
							let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance)

//							try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported), docID: docId)
							let bindingKeys = try await initSecurityKeys(algSupported: Set(configuration.credentialSigningAlgValuesSupported))

//							let issuanceOutcome = try await issueOfferedCredentialInternalValidated(authRequest, offer: offer, issuer: issuer, configuration: configuration, claimSet: nil)
							let issuanceOutcome = try await submissionUseCase(authorizedRequest, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys)

//							let authReqParams = convertAuthorizedRequestToParam(authorizedRequest: authRequest)
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
//			let bindingKeys = try await initSecurityKeys(algSupported: Set(configuration.credentialSigningAlgValuesSupported))
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
//			guard case .authorized(let authorized) = authorizedOutcome else {
//				throw PresentationSession.makeError(str: "Invalid authorized request outcome")
//			}
//			let outcome = try await submissionUseCase(authorized, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys)
//			return (outcome, configuration.format)
		} else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}
	}

	/*private func issueByPARType_old(_ docTypeIdentifier: DocTypeIdentifier, promptMessage: String? = nil, wia: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome, DocDataFormat) {
//		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
//		let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		
		switch issuerMetadata {
		case .success(let metaData):
			if let authorizationServer = metaData.authorizationServers?.first {
				let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
				let configuration = try getCredentialIdentifier(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
				//				try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
				
				let dPopConstructor = DPoPConstructor(algorithm: JWSAlgorithm(.ES256), jwk: wia.jwk, privateKey: .secKey(wia.privateKey))
				// Authorize with auth code flow
				let issuer = try await getIssuer(offer: offer, with: dPopConstructor)
				
				let authorizedOutcome = (try await authorizePARWithAuthCodeUseCase(issuer: issuer, offer: offer, wia: wia)).1
				if case .presentation_request(let url) = authorizedOutcome, let parRequested {
					logger.info("Dynamic issuance request with url: \(url)")
					let uuid = UUID().uuidString
					Self.metadataCache[uuid] = offer
					let outcome = IssuanceOutcome.pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: parRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: parRequested.pkceVerifier.codeVerifierMethod ))
					return (outcome, configuration.format)
				}
				guard case .authorized(let authorized) = authorizedOutcome else { throw WalletError(description: "Invalid authorized request outcome") }
				let outcome = try await issueOfferedCredentialInternal(authorized, issuer: issuer, configuration: configuration, claimSet: claimSet)
				return (outcome, configuration.format)
			} else {
				throw WalletError(description: "Invalid authorization server")
			}
		case .failure:
			throw WalletError(description: "Invalid issuer metadata")
		}
	}*/

//	private func getIssuer(offer: CredentialOffer, with dPopConstructor: DPoPConstructorType) async throws -> Issuer {
//		try await MainActor.run {
//			try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession), dpopConstructor: dPopConstructor)
//		}
//	}

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
//			OpenId4VCIService.parReqCache = request
			self.authRequested = authRequested
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(pushedAuthorizationRequestEndpoint)")

			return .presentation_request(authRequested.authorizationCodeURL.url)
		} else if case let .failure(failure) = parPlaced {
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		throw WalletError(description: "Failed to get push authorization code request")
	}

//	private func authorizePARWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer, wia: IssuerDPoPConstructorParam) async throws -> (AuthorizedRequest?, AuthorizeRequestOutcome?) {
//		var pushedAuthorizationRequestEndpoint = ""
//		if case let .oidc(metaData) = offer.authorizationServerMetadata,
//		   let endpoint = metaData.pushedAuthorizationRequestEndpoint {
//			pushedAuthorizationRequestEndpoint = endpoint
//		} else if case let .oauth(metaData) = offer.authorizationServerMetadata,
//				  let endpoint = metaData.pushedAuthorizationRequestEndpoint {
//			pushedAuthorizationRequestEndpoint = endpoint
//		}
//		guard !pushedAuthorizationRequestEndpoint.isEmpty else { throw WalletError(description: "pushed Authorization Request Endpoint is nil") }
//		logger.info("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
//		
//		let parPlaced = try await issuer.pushAuthorizationCodeRequest(credentialOffer: offer)
//		
//		if case let .success(request) = parPlaced,
//		   case let .par(parRequested) = request {
//			OpenId4VCIService.parReqCache = request
//			self.parRequested = parRequested
//			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
//			
//			return (nil, .presentation_request(parRequested.getAuthorizationCodeURL.url))
//			
//		} else if case let .failure(failure) = parPlaced {
//			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
//		}
//		throw WalletError(description: "Failed to get push authorization code request")
//	}
	
	/*private func handleAuthorizationCodeBothCases(issuer: Issuer, request: UnauthorizedRequest, authorizationCode: String) async throws -> AuthorizedRequest {
		let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
		switch unAuthorized {
		case .success(let request):
			let authorizedRequest = await issuer.authorizeWithAuthorizationCode(authorizationCode: request)
			
			if case let .success(authorized) = authorizedRequest {
				if case let .proofRequired(token,_, _, _, _, _) = authorized {
					let at = token.accessToken;    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
					return authorized
				} else if case let .success(authorized) = authorizedRequest,
						  case let .noProofRequired(token,_, _, _, _) = authorized {
					let at = token.accessToken;    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
					return authorized
				}
			}
			throw WalletError(description: "Failed to get access token")
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}*/

	/*private func convertAuthorizedRequestToParam(authorizedRequest: AuthorizedRequest) -> AuthorizedRequestParams? {
//		AuthorizedRequestParams(accessToken: authorizedRequest.accessToken.accessToken, refreshToken: authorizedRequest.refreshToken?.refreshToken, cNonce: <#T##String?#>, timeStamp: <#T##TimeInterval#>, dPopNonce: <#T##Nonce?#>)

		var authReqParams: AuthorizedRequestParams? = nil
		switch authorizedRequest {
		case .noProofRequired(let accessToken, let refreshToken, _, let timeStamp, let dPopNonce):
			authReqParams = AuthorizedRequestParams(accessToken: accessToken.accessToken, refreshToken: refreshToken?.refreshToken, cNonce: nil, timeStamp: timeStamp, dPopNonce: dPopNonce)
		case .proofRequired(let accessToken, let refreshToken, let cNonce, _, let timeStamp, let dPopNonce):
			authReqParams = AuthorizedRequestParams(accessToken: accessToken.accessToken, refreshToken: refreshToken?.refreshToken, cNonce: cNonce.value, timeStamp: timeStamp, dPopNonce: dPopNonce)
		}
		return authReqParams

	}*/
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
