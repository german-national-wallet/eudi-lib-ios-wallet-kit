//
//  Untitled.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 15.10.25.
//
import Foundation

public struct RelyingPartyInfo {
	public let version: String
	public let issuer: String
	public let validFrom: Date
	public let validTo: Date
	public let serialNumber: String
	public let signatureAlgorithm: String
	public var country: String? = nil

	public init(version: String, issuer: String, validFrom: Date, validTo: Date, serialNumber: String, signatureAlgorithm: String, country: String? = nil) {
		self.version = version
		self.issuer = issuer
		self.validFrom = validFrom
		self.validTo = validTo
		self.serialNumber = serialNumber
		self.signatureAlgorithm = signatureAlgorithm
		self.country = country
	}
}
