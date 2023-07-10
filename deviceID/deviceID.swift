//
//  deviceID.swift
//  deviceID
//
//  Created by Yaniv Assaf on 13/06/2023.
//

import Foundation
import UIKit
import CoreTelephony
import LocalAuthentication

class Auth: Codable {
    var key: String
    var secret: String
    
    init(key: String, secret: String) {
        self.key = key
        self.secret = secret
    }
}

struct IdentificationResponse: Codable {
    let visit_id: String
    let device_id: String
    let device_found: Bool
    let unique: Float
    let os: String
    let os_version: String
    let threat: Int
    let violation: Violation
    let blocked: Bool
    let first_seen: String
    let last_seen: String
    let ip: String
    let request_id: String
    let data: String
}

struct Violation: Codable {
    let tempered: Bool
    let confidence: Float
    
    enum CodingKeys: String, CodingKey {
        case tempered, confidence
    }
}

class Identification: Codable {
    
    var localeIdentifier: String
    var interfaceStyle: Int
    var deviceName: String
    var vendorID: String
    var systemName: String
    var systemVersion: String
    var macOSVersion: String
    var resolution: Array<CGFloat>
    var scale: CGFloat
    var memory: UInt64
    var cores: Int
    var availableSpace: String
    var hostName: String
    var timezone: String
    var mobileCountryCode: String
    var mobileNetworkCode: String
    var auth: Bool
    var bioAuth: Bool
    var saved: String
    var start: Int64
    var token: String
    var request_id: String
    var data: String
    
     init() {
        self.interfaceStyle = UIUserInterfaceStyle.RawValue()
        self.deviceName = UIDevice.current.name
        self.vendorID = UIDevice.current.identifierForVendor?.uuidString ?? "0000"
        self.systemName = UIDevice.current.systemName
        self.systemVersion = UIDevice.current.systemVersion
        self.macOSVersion = ProcessInfo.processInfo.operatingSystemVersionString
        self.resolution = [UIScreen.main.bounds.width, UIScreen.main.bounds.height]
        self.scale = UIScreen.main.scale
        self.scale = UIScreen.main.scale
        self.memory = ProcessInfo.processInfo.physicalMemory
        self.cores = ProcessInfo.processInfo.activeProcessorCount
        self.auth = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
        self.bioAuth = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        self.hostName = ProcessInfo.processInfo.hostName
        self.timezone = TimeZone(abbreviation: "NZST")?.identifier ?? "0"
        self.mobileCountryCode = CTCarrier().mobileCountryCode ?? "0"
        self.mobileNetworkCode = CTCarrier().mobileNetworkCode ?? "0"
        self.localeIdentifier = Locale.current.identifier
        if let totalSpaceInBytes = FileManagerUility.getFileSize(for: .systemSize) {
           /// If you want to convert into GB then call like this
            self.availableSpace = FileManagerUility.convert(totalSpaceInBytes) ?? "0"
        } else {
            self.availableSpace = "0"
        }
         let data = keychainRead(service: "deviceID-token", account: "multi")
         if (data != nil) {
             self.saved = String(data: data!, encoding: .utf8)!
         } else {
             self.saved = ""
         }
         self.start = Date.timestamp
         self.token = ""
         self.request_id = ""
         self.data = ""
    }
    
    func setKey(key: String) {
        self.token = key
    }

}

func keychainSave(_ data: Data, service: String, account: String) {
    
    // Create query
    let query = [
        kSecValueData: data,
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
    ] as CFDictionary
    
    // Add data in query to keychain
    let status = SecItemAdd(query, nil)
    
    if status != errSecSuccess {
        // Print out the error
        print("Error: \(status)")
    }
}

func keychainRead(service: String, account: String) -> Data? {
    
    let query = [
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecClass: kSecClassGenericPassword,
        kSecReturnData: true
    ] as CFDictionary
    
    var result: AnyObject?
    SecItemCopyMatching(query, &result)
    
    return (result as? Data)
}

final class deviceID {
    
    static let standard = deviceID();
    var identifier: Identification;
    var JSONID: Data?;
    var loaded = ""
    
    init() {
        self.identifier = Identification();
    }
    
    func load(apiKey: String, secret: String, completion: @escaping (_ data: String?, _ error: Error?)->()) {
        let url = URL(string: "https://freelancecloud.ddns.net:3001/load")!
        var request = URLRequest(url: url)
        request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"
        let encoder = JSONEncoder()
        let dataString = try! encoder.encode(Auth(key: apiKey, secret: secret))
        request.httpBody = dataString
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard
                let data = data,
                let response = response as? HTTPURLResponse,
                error == nil
            else {
                completion(nil, error ?? URLError(.badServerResponse))
                return
            }
            
            guard (200 ... 299) ~= response.statusCode else {                    // check for http errors
                print("statusCode should be 2xx, but is \(response.statusCode)")
                print("response = \(response)")
                completion(nil, response.statusCode as? Error)
                return
            }
            
                let token = String(data: data, encoding: .utf8)!
                self.loaded = token
                self.identifier.setKey(key: token)
                completion(token, nil)
        }
        task.resume()
    }
    
    func id(tag: String?, request_id: String?, completion: @escaping (_ data: IdentificationResponse?, _ error: Error?)->()) {
            let url = URL(string: "https://freelancecloud.ddns.net/ios")!
        var request = URLRequest(url: url)
        request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(loaded)", forHTTPHeaderField: "Authorization")
        request.httpMethod = "POST"
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        self.identifier.data = tag ?? ""
        self.identifier.request_id = request_id ?? ""
        self.JSONID = try! encoder.encode(self.identifier)
        request.httpBody = self.JSONID
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard
                let data = data,
                let response = response as? HTTPURLResponse,
                error == nil
            else {                                                               // check for fundamental networking error
                completion(nil, error ?? URLError(.badServerResponse))
                return
            }
            
            guard (200 ... 299) ~= response.statusCode else {                    // check for http errors
                completion(nil, response.statusCode as? Error)
                return
            }
            
            // do whatever you want with the `data`, e.g.:
            print(data)
            do {
                let responseObject = try JSONDecoder().decode(IdentificationResponse.self, from: data)
                print(responseObject)
                completion(responseObject, nil)
            } catch {
                print(error)
                completion(nil, error)
            }
        }
        task.resume()
    }
    
}

struct FileManagerUility {

    static func getFileSize(for key: FileAttributeKey) -> Int64? {
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)

        guard
            let lastPath = paths.last,
            let attributeDictionary = try? FileManager.default.attributesOfFileSystem(forPath: lastPath) else { return nil }

        if let size = attributeDictionary[key] as? NSNumber {
            return size.int64Value
        } else {
            return nil
        }
    }

    static func convert(_ bytes: Int64, to units: ByteCountFormatter.Units = .useGB) -> String? {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = units
        formatter.countStyle = ByteCountFormatter.CountStyle.decimal
        formatter.includesUnit = false
        return formatter.string(fromByteCount: bytes)
    }

}

extension Date {
    static var timestamp: Int64 {
        return Int64(Date().timeIntervalSince1970 * 1000)
    }
}
