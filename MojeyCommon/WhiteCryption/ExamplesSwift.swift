/*****************************************************************
|
|   whiteCryption Secure Key Box
|
|   $Id: ExamplesSwift.swift 9864 2017-07-05 16:24:39Z gkaksis $
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


var exampleNum = 0
var numFailures = 0

func PrintExampleHeader(_ text:String)
{
    exampleNum = exampleNum + 1
    NSLog("Example #%d: %@", exampleNum, text)
}

func PrintExampleFooter()
{
    NSLog("\n========================================\n")
}

func DumpSecureDataInfo(_ data:OpaquePointer?)
{
    var info = SKB_DataInfo();
    SKB_CHECK(SKB_SecureData_GetInfo(data, &info));
    var type:String;
    switch (info.type)
    {
    case SKB_DATA_TYPE_BYTES:
        type = "raw bytes (symmetric key?)";
        break;
    case SKB_DATA_TYPE_RSA_PRIVATE_KEY:
        type = "RSA private key";
        break;
    case SKB_DATA_TYPE_ECC_PRIVATE_KEY:
        type = "ECC private key";
        break;
    default:
        type = "[error] unknown type";
    }
    NSLog("Data type: %@", type);
    NSLog("Data size: %d", info.size);
}

func PrintBytes(buffer:[SKB_Byte], buffer_size:Int)
{
    let BYTES_PER_LINE = 8 // how many bytes should be printed in each line?

    var line = String()
    var n = 0
    while (n < buffer_size)
    {
        line += String(format: "0x%02X, ", buffer[n])
        if (n % BYTES_PER_LINE == BYTES_PER_LINE - 1)
        {
            NSLog("%@", line)
            line = String()
        }
        n = n + 1
    }
    if (buffer_size % BYTES_PER_LINE != 0)
    {
        NSLog("%@", line)
    }
}

func SKB_CHECK(_ result:SKB_Result, file: String = #file, line: Int = #line)
{
    if (result != SKB_SUCCESS)
    {
        NSLog("SKB failed on line \(line) of \(file)");
        numFailures = numFailures + 1
    }
}

extension String {

    func toSKBPointer() -> UnsafePointer<SKB_Byte>? {
        guard let data = self.data(using: String.Encoding.utf8) else { return nil }

        var buffer:UnsafePointer<SKB_Byte>? = nil

        let p = data.toUnsafePointerBytes
        //data.withUnsafeBytes({ (p: UnsafePointer<UInt8>) -> Void in
            buffer = UnsafePointer<SKB_Byte>(p)
        //})

        return buffer
    }
}


extension Data {

    func toSKBPointer() -> UnsafePointer<SKB_Byte>? {
        let data = self

        var buffer:UnsafePointer<SKB_Byte>? = nil

        let p = data.toUnsafePointerBytes
        //data.withUnsafeBytes({ (p: UnsafePointer<UInt8>) -> Void in
            buffer = UnsafePointer<SKB_Byte>(p)
        //})

        return buffer
    }
}
