/*****************************************************************
|
|   whiteCryption Secure Key Box
|
|   $Id: ExampleCreateSignatureEcdsaSha.swift 9864 2017-07-05 17:32:39Z gkaksis $
|
|   This software is provided to you pursuant to your Software
|   license agreement (SLA) with whiteCryption Corporation
|   ("whiteCryption") and Intertrust Technologies Corporation
|   ("Intertrust"). This software may be used only in accordance
|   with the terms of this agreement.
|
|   Copyright (c) 2000-2019, whiteCryption Corporation. All rights reserved.
|   Copyright (c) 2004-2019, Intertrust Technologies Corporation. All rights reserved.
|
****************************************************************/

import Foundation
//import Skb.Platform
//import Skb.SecureKeyBox
//import Skb.Configuration

class WhiteCryptionSign {

    static let `default` = WhiteCryptionSign()

    // It is actually SKB_Engine, but Swift can not process/import C++ structures correctly (it simply ignores any typedef containing C++ structs)
    var engine:OpaquePointer?

    init() {
        let result = SKB_Engine_GetInstance(&engine)
        if (result != SKB_SUCCESS)
        {
            if (result == SKB_ERROR_EVALUATION_EXPIRED)
            {
                NSLog("Secure Key Box cannot be used because the evaluation period has expired.")
            }
            else
            {
                NSLog("Failed to get engine instance!")
            }
            exit(1)
        }
    }


    func sign(message: Data) -> Data? {

        // prepare secured ECC private key; this key must NOT be released before the transform object that uses it is released
        var secure_key:OpaquePointer?
        SKB_Engine_CreateDataFromExported(engine, EXPORTED_SHOWER_KEY, SKB_Size(EXPORTED_SHOWER_KEY.count), &secure_key)

        // initialize parameters; for ECDSA, it must be SKB_SignTransformParametersEx
        var ecc_params = SKB_EccParameters(
            curve: SKB_ECC_CURVE_NIST_256,
            curve_parameters: nil,
            random_value: nil
        )

        var params = SKB_SignTransformParametersEx(
            base: SKB_SignTransformParameters(
                algorithm: SKB_SIGNATURE_ALGORITHM_ECDSA,
                key: secure_key
            ),
            extension: &ecc_params
        )

        // initialize transform object
        var transform:OpaquePointer?
        SKB_Engine_CreateTransform(engine, SKB_TRANSFORM_TYPE_SIGN, &params, &transform)

        //print(message)
        let messageSha256 = message.sha256

        // add message
        guard let messagePointer = messageSha256.toSKBPointer() else { return nil }
        SKB_Transform_AddBytes(transform, messagePointer, SKB_Size(messageSha256.count))

        // generate signature
        var signature = [SKB_Byte](repeating: 0, count: 1024) // should be enough
        var signature_size = SKB_Size(signature.count)
        SKB_Transform_GetOutput(transform, &signature, &signature_size)


        let sigData = Data(signature).prefix(Int(signature_size))

        // release resources
        SKB_Transform_Release(transform)
        SKB_SecureData_Release(secure_key)

        return sigData
    }

    func verify(signature: Data, message: Data) -> Bool {
        guard signature.count == 64 else { return false }
        let r = signature[0...31]
        let s = signature[32...63]
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("r: \(r.hex)")
        print("s: \(s.hex)")
        let ecdsaSig1 = EcdsaSignature(r: r, s: s)
        let ecdsaSig2 = EcdsaSignature(der: ecdsaSig1.der, requireLowS: true, curve: .r1)!
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("r: \(ecdsaSig2.r.hex)")
        print("s: \(ecdsaSig2.s.hex)")

        let messageSha256 = message.sha256

        let key0 = try! EccRecoverKey.recoverPublicKey(signatureDer: ecdsaSig1.der, message: messageSha256, recid: 0)
        let key1 = try! EccRecoverKey.recoverPublicKey(signatureDer: ecdsaSig1.der, message: messageSha256, recid: 1)
        let publicKey = PUBLIC_SHOWER_KEY

        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print(publicKey.hex)
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print(key0.hex)
        print(key1.hex)
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

        let keychain = Keychain(accessGroup: Constants.accessGroup)
        let verify1 = try? keychain.verifyWithEllipticCurvePublicKey(keyData: publicKey, message: message, signature: ecdsaSig1.der)
        print("APPLE VERIFY1 = \(verify1!)")
        let verify2 = try? keychain.verifyWithEllipticCurvePublicKey(keyData: publicKey, message: message, signature: ecdsaSig2.der)
        print("APPLE VERIFY2 = \(verify2!)")

        return (publicKey == key0 || publicKey == key1)

    }

    func test() {
        var v = 0
        for _ in 0...1 {
            let message = "Hello".data(using: .utf8)!
            guard let signature = sign(message: message) else {
                print("FAILED :(")
                return
            }
            if verify(signature: signature, message: message) {
                print("VERIFIED!")
                v = v + 1
            } else {
                print("FAILED :(")
            }
        }
        print("v = \(v)")

    }


    deinit {
        // release engine
        let result = SKB_Engine_Release(engine)
        if (result != SKB_SUCCESS)
        {
            numFailures = numFailures + 1
            NSLog("Failed to release the engine")
        }

        //Return 0 if no failures.
        if (numFailures != 0)
        {
            NSLog("%i errors encountered while executing examples!", numFailures)
            exit(1)
        }
        else
        {
            NSLog("SkbExamplesSwift finished successfully.")
        }
    }

}
