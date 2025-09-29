//
//  EudiWallet+Extension.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 19.12.24.
//

import Foundation
import MdocDataModel18013
import WalletStorage
import LocalAuthentication
import OpenID4VCI
import SwiftyJSON

extension EudiWallet {
    @MainActor
    @discardableResult public func issuePAR(docTypeIdentifier: DocTypeIdentifier, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, dpopConstructorParam: IssuerDPoPConstructorParam) async throws -> WalletStorage.Document? {
		let usedKeyOptions = try await validateKeyOptions(docTypeIdentifier: docTypeIdentifier, keyOptions: keyOptions)
//		let (issueReq, openId4VCIService) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
		let openId4VCIService = try await prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: nil, keyOptions: usedKeyOptions, disablePrompt: false, promptMessage: promptMessage)

		let (issuance, dataFormat) = try await openId4VCIService.issuePAR(docTypeIdentifier, promptMessage: promptMessage, dpopConstructorParam: dpopConstructorParam)
		guard let issuance else {
			return nil
		}

		return try await finalizeIssuing(issueOutcome: issuance, docType: docTypeIdentifier.docType, format: dataFormat, issueReq: openId4VCIService.issueReq, openId4VCIService: openId4VCIService)
    }
	
	@MainActor
	@discardableResult public func resumePendingIssuanceDocuments(pendingDoc: WalletStorage.Document, authorizationCode: String, keyOptions: KeyOptions? = nil) async throws -> (WalletStorage.Document?, AuthorizedRequest?) {

		guard pendingDoc.status == .pending, let docTypeIdentifier = pendingDoc.docTypeIdentifier else {
			throw PresentationSession.makeError(str: "Invalid document status for pending issuance: \(pendingDoc.status)")
		}
		let usedKeyOptions = try await validateKeyOptions(docTypeIdentifier: docTypeIdentifier, keyOptions: keyOptions)
		let openId4VCIService = try await prepareIssuing(id: pendingDoc.id, docTypeIdentifier: docTypeIdentifier, displayName: nil, keyOptions: usedKeyOptions, disablePrompt: true, promptMessage: nil)
		let (outcome, authRequest) = try await openId4VCIService.resumePendingIssuance(pendingDoc: pendingDoc, authorizationCode: authorizationCode)
		if case .pending(_) = outcome { return (pendingDoc, nil) }
		let res = try await finalizeIssuing(issueOutcome: outcome, docType: pendingDoc.docType, format: pendingDoc.docDataFormat, issueReq: openId4VCIService.issueReq, openId4VCIService: openId4VCIService)
		return (res, authRequest)

		/*guard pendingDoc.status == .pending,
				let docTypeIdentifier = pendingDoc.docTypeIdentifier  else { throw WalletError(description: "Invalid document status") }

		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		var openId4VCIServices = [(IssueRequest, OpenId4VCIService)]()
		for _ in 1...batchCount {
			let id = UUID().uuidString
			let (issueReq, openId4VCIService) = try await prepareIssuingService(id: id, docType: pendingDoc.docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
			openId4VCIServices.append((issueReq, openId4VCIService))
		}
		
		let issueRequestsIds = openId4VCIServices.map{ $0.0.id }

		let (issuanceOutcome, authorizedRequestParams) = try await openId4VCIServices.first!.1.resumePendingIssuance(pendingDoc: pendingDoc, authorizationCode: authorizationCode, batchCount: batchCount, issueRequestsIds: issueRequestsIds)
		
		var documents = [WalletStorage.Document]()
		if let document = await saveCredentials(docType: pendingDoc.docType, docDataFormat: docDataFormat, issueReq: openId4VCIServices, issuanceOutcome: issuanceOutcome) {
			documents.append(document)
		}
		return (documents.first, authorizedRequestParams)*/
	}
	
	/*private func saveCredentials(docType: String?, docDataFormat: DocDataFormat, issueReq: [(IssueRequest, OpenId4VCIService)], issuanceOutcome: IssuanceOutcome) async -> WalletStorage.Document? {
		var document: WalletStorage.Document?
		
		do {
			switch issuanceOutcome {
			case .issued(let jsonData, let str, let cc):
				if let str = str {
					let credentials = str.components(separatedBy: ",")
					for (index, credential) in credentials.enumerated() {
						if let (issueRequest, openId4VCIService) = issueReq[safe: index] {
							document = try await finalizeIssuing(issueOutcome: .issued(Data(base64URLEncoded: credential), credential, cc), docType: docType, format: docDataFormat, issueReq: issueRequest, openId4VCIService: openId4VCIService)
						}
					}
				} else {
					guard let jsonData else {throw WalletError.generic("unable to finalizeIssuing") }
					
					let jsonObject = try? JSON(data: jsonData)
					if let credentials = jsonObject?.arrayObject as? [String] {
						for (index, credential) in credentials.enumerated() {
							if let (issueRequest, openId4VCIService) = issueReq[safe: index] {
								document = try await finalizeIssuing(issueOutcome: .issued(credential.data(using: .utf8), credential, cc), docType: docType, format: docDataFormat, issueReq: issueRequest, openId4VCIService: openId4VCIService)
							}
						}
					} else {
						print("Failed to parse JSON as an array of strings")
					}
				}
			default:
				print(#function, "Unhandled issuance outcome")
			}
		} catch {
			return nil
		}
		
		return document

	}*/

	@MainActor
	public func getCredentials(with refreshToken: String, accessToken: String, docType: String?, identifier: String?, scope: String?, docTypeIdentifier: DocTypeIdentifier, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, docDataFormat: DocDataFormat, issuerDPopConstructorParam: IssuerDPoPConstructorParam, batchCount: Int) async -> (WalletStorage.Document?, AuthorizedRequest?) {
		do {
			var openId4VCIServices = [(IssueRequest, OpenId4VCIService)]()
			for _ in 1...batchCount {
				let id = UUID().uuidString
				let (issueReq, openId4VCIService) = try await prepareIssuingService(id: id, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
				openId4VCIServices.append((issueReq, openId4VCIService))
			}
			let authRequest = AuthorizedRequest(accessToken: try IssuanceAccessToken(accessToken: accessToken, tokenType: .none), refreshToken: try IssuanceRefreshToken(refreshToken: refreshToken), credentialIdentifiers: nil, timeStamp: 3600, dPopNonce: nil)

//			let authRequest: AuthorizedRequest = .noProofRequired(accessToken: try IssuanceAccessToken(accessToken: accessToken, tokenType: .none), refreshToken: try IssuanceRefreshToken(refreshToken: refreshToken), credentialIdentifiers: nil, timeStamp: 3600, dPopNonce: nil)
			
			if let credentialsOutcome = try openId4VCIServices.first {
				let credentialsOutcome = try await credentialsOutcome.1.getCredentialsWithRefreshToken(docTypeIdentifier: docTypeIdentifier, authorizedRequest: authRequest, issuerDPopConstructorParam: issuerDPopConstructorParam, docId: credentialsOutcome.0.id)

				guard let issuanceOutcome = credentialsOutcome.0,
						let _ = credentialsOutcome.1,
						let authorizedRequestParams = credentialsOutcome.2 else {
					throw  WalletError(description: "Error in getting access token")
				}

				var documents = [WalletStorage.Document]()
				for i in 0..<batchCount {
					let (issueReq, openId4VCIService) = openId4VCIServices[i]
					let document = (try await finalizeIssuing(issueOutcome: issuanceOutcome, docType: docType, format: docDataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService))
					documents.append(document)
				}
				return (documents.first, authorizedRequestParams)

			}
//			let credentialsOutcome = try await openId4VCIServices.first.1.getCredentialsWithRefreshToken(docType, scope: scope, claimSet: nil, identifier: identifier, authorizedRequest: authRequest, issuerDPopConstructorParam: issuerDPopConstructorParam, docId: openId4VCIServices.first!.0.id)
			return (nil, nil)
		} catch {
			return (nil, nil)
		}
	}

//	private func saveCredentials(docType: String?, docDataFormat: DocDataFormat, issueReq: IssueRequest, openId4VCIService: OpenId4VCIService, issuanceOutcome: IssuanceOutcome) async -> WalletStorage.Document? {
//		var document: WalletStorage.Document?
//		document = try await finalizeIssuing(issueOutcome: issuanceOutcome, docType: docType, format: docDataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
//
//		return document
//	}

    private func prepareIssuingService(id: String, docType: String?, displayName: String?, keyOptions: KeyOptions?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService) {
        guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
		
        let issueReq = try await Self.authorizedAction(action: {
            return try await beginIssueDocument(id: id, keyOptions: keyOptions)
        }, disabled: !userAuthenticationRequired || docType == nil, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(displayName ?? docType ?? "", comment: "")))
        guard let issueReq else { throw LAError(.userCancel)}
		let openId4VCIService = await OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, uiCulture: uiCulture, config: openID4VciConfig.toOpenId4VCIConfig(), cacheIssuerMetadata: true, networking: networkingVci)

//        let openId4VCIService = await OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, uiCulture: uiCulture, config: openID4VciConfig .toOpenId4VCIConfig(), urlSession: urlSession)
        return (issueReq, openId4VCIService)
    }
}
