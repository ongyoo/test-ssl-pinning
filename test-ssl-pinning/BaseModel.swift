//
//  BaseModel.swift
//  test-ssl-pinning
//
//  Created by Sutham on 8/16/2560 BE.
//  Copyright © 2560 Komsit. All rights reserved.
//


import Alamofire

class BaseModel: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    var urlSession: Foundation.URLSession!
    var serverTrustPolicy: ServerTrustPolicy!
    var serverTrustPolicies: [String: ServerTrustPolicy]!
    var afManager: SessionManager!
    
    let githubCert = "*.claimdi.com"
    let corruptedCert = "corrupted"
    
    override init() {
        super.init()
        self.setConfig()
    }
    
    func sendRequest(url: String, completion : @escaping (_ result: DataResponse<Any>) -> ()) {
        afManager.request(URL(string: url)!, method: .get, parameters: nil, encoding: JSONEncoding.default, headers: nil)
            .responseJSON { response in
                completion(response)
        }
    }
    
    func setConfig() {
        let pathToCert = Bundle.main.path(forResource: githubCert, ofType: "cer")
        let localCertificate:Data = try! Data(contentsOf: URL(fileURLWithPath: pathToCert!))
        self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
        self.configureURLSession()
    }
    
    // MARK: SSL Config
    
    func configureAlamoFireSSLPinningWithCertificateData(_ certificateData: Data) {
        self.serverTrustPolicy = ServerTrustPolicy.pinCertificates(
            // Getting the certificate from the certificate data
            certificates: [SecCertificateCreateWithData(nil, certificateData as CFData)!],
            // Choose to validate the complete certificate chain, not only the certificate itself
            validateCertificateChain: true,
            // Check that the certificate mathes the host who provided it
            validateHost: true
        )
        
        self.serverTrustPolicies = [
            "sg-income.claimdi.com": self.serverTrustPolicy!
        ]
        
        let configuration = URLSessionConfiguration.default
        configuration.httpAdditionalHeaders = Alamofire.SessionManager.defaultHTTPHeaders
        // Time out
        configuration.timeoutIntervalForRequest = 60.0
        configuration.timeoutIntervalForResource = 60.0
        
        self.afManager = SessionManager(
            configuration: configuration,
            serverTrustPolicyManager: ServerTrustPolicyManager(policies: self.serverTrustPolicies)
        )
    }
    
    func configureURLSession() {
        self.urlSession = Foundation.URLSession(configuration: URLSessionConfiguration.default, delegate: self, delegateQueue: nil)
    }
    
    // MARK: URL session delegate
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let serverTrust = challenge.protectionSpace.serverTrust
        let certificate = SecTrustGetCertificateAtIndex(serverTrust!, 0)
        
        // Set SSL policies for domain name check
        let policies = NSMutableArray();
        policies.add(SecPolicyCreateSSL(true, (challenge.protectionSpace.host as CFString?)))
        SecTrustSetPolicies(serverTrust!, policies);
        
        // Evaluate server certificate
        var result: SecTrustResultType = SecTrustResultType(rawValue: 0)!
        SecTrustEvaluate(serverTrust!, &result)
        let isServerTrusted:Bool = (result == SecTrustResultType.unspecified || result == SecTrustResultType.proceed)
        /* old
        var certName = ""
        if self.isSimulatingCertificateCorruption {
            certName = corruptedCert
        } else {
            certName = githubCert
        }
         */
        let certName = githubCert
        
        // Get local and remote cert data
        let remoteCertificateData:Data = SecCertificateCopyData(certificate!) as Data
        let pathToCert = Bundle.main.path(forResource: certName, ofType: "cer")
        let localCertificate:Data = try! Data(contentsOf: URL(fileURLWithPath: pathToCert!))
        
        if (isServerTrusted && (remoteCertificateData == localCertificate)) {
            let credential:URLCredential = URLCredential(trust: serverTrust!)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
