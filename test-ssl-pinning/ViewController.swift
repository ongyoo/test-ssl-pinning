//
//  ViewController.swift
//  test-ssl-pinning
//
//  Created by Sutham on 8/16/2560 BE.
//  Copyright © 2560 Komsit. All rights reserved.
//

import UIKit
import Alamofire

class ViewController: UIViewController, URLSessionDelegate, URLSessionTaskDelegate {
    
    @IBOutlet weak var urlTextField: UITextField!
    @IBOutlet weak var responseTextView: UITextView!
    @IBOutlet weak var certificateCorruptionButton: UIButton!
    @IBOutlet weak var activityIndicator: UIActivityIndicatorView!
    
//    let githubCert = "github.com"
//    let corruptedCert = "corrupted"
    
    let githubCert = "*.claimdi.com"
    let corruptedCert = "corrupted"
    let baseModel = BaseModel()
    
    var urlSession: Foundation.URLSession!
    var serverTrustPolicy: ServerTrustPolicy!
    var serverTrustPolicies: [String: ServerTrustPolicy]!
    var afManager: Alamofire.SessionManager!
    
    var isSimulatingCertificateCorruption = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let pathToCert = Bundle.main.path(forResource: githubCert, ofType: "cer")
        let localCertificate:Data = try! Data(contentsOf: URL(fileURLWithPath: pathToCert!))
        self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
        self.configureURLSession()
        
        self.activityIndicator.hidesWhenStopped = true
    }
    
    // MARK: Button actions
    
    @IBAction func alamoFireRequestHandler(_ sender: UIButton) {
        self.activityIndicator.startAnimating()
        if let urlText = self.urlTextField.text {
            self.afManager.request(URL(string: urlText)!).response(completionHandler: { (response) in
                self.activityIndicator.stopAnimating()
                
                guard let data = response.data, response.error == nil else {
                    self.responseTextView.text = response.error!.localizedDescription
                    self.responseTextView.textColor = UIColor.red
                    return
                }
                
                self.responseTextView.text = String(data: data, encoding: String.Encoding.utf8)!
                self.responseTextView.textColor = UIColor.black
            })
        }
    }
    
    @IBAction func nsurlSessionRequestHandler(_ sender: UIButton) {
        self.activityIndicator.startAnimating()
        self.urlSession?.dataTask(with: URL(string:self.urlTextField.text!)!, completionHandler: { ( data,  response,  error) -> Void in
            DispatchQueue.main.async(execute: { () -> Void in
                self.activityIndicator.stopAnimating()
            })
            
            guard let data = data, error == nil else {
                DispatchQueue.main.async(execute: { () -> Void in
                    self.responseTextView.text = error!.localizedDescription
                    self.responseTextView.textColor = UIColor.red
                })
                return
            }
            
            DispatchQueue.main.async(execute: { () -> Void in
                self.responseTextView.text = String(data: data, encoding: String.Encoding.utf8)
                self.responseTextView.textColor = UIColor.black
            })
        }).resume()
    }
    
    @IBAction func toggleCertificateSimulation(_ sender: AnyObject) {
        if self.isSimulatingCertificateCorruption == true {
            self.isSimulatingCertificateCorruption = false;
            let pathToCert = Bundle.main.path(forResource: githubCert, ofType: "cer")
            let localCertificate:Data = try! Data(contentsOf: URL(fileURLWithPath: pathToCert!))
            self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
            self.certificateCorruptionButton.setTitleColor(self.certificateCorruptionButton.tintColor, for: UIControlState())
            self.certificateCorruptionButton.setTitle("Simulate certificate corruption", for: UIControlState())
        } else {
            self.isSimulatingCertificateCorruption = true
            let pathToCert = Bundle.main.path(forResource: corruptedCert, ofType: "cer")
            let localCertificate:Data = try! Data(contentsOf: URL(fileURLWithPath: pathToCert!))
            self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
            self.certificateCorruptionButton.setTitleColor(UIColor.red, for: UIControlState())
            self.certificateCorruptionButton.setTitle("Simulating certificate corruption", for: UIControlState())
        }
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
        
        self.afManager = Alamofire.SessionManager(
            configuration: URLSessionConfiguration.default,
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
        let isServerTrusted: Bool = (result == SecTrustResultType.unspecified
            || result == SecTrustResultType.proceed)
        
        var certName = ""
        
        if self.isSimulatingCertificateCorruption {
            certName = corruptedCert
        } else {
            certName = githubCert
        }
 
        
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
