//
//  Bech32.swift
//
//  Created by Evolution Group Ltd on 12.02.2018.
//  Copyright © 2018 Evolution Group Ltd. All rights reserved.
//

//  Base32 address format for native v0-16 witness outputs implementation
//  https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//  Inspired by Pieter Wuille C++ implementation
/// Bech32 checksum implementation
public class Bech32 {
    private let gen: [UInt32] = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ]

    /// Bech32 checksum delimiter (ASCII code for '1' is 0x31)
    private let checksumMarker: UInt8 = 0x31

    /// Bech32 character set for encoding
    private let encCharset: [UInt8] = {
        // "qpzry9x8gf2tvdw0s3jn54khce6mua7l" in ASCII
        return Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    }()

    /// Bech32 character set for decoding (128 entries for ASCII range)
    private let decCharset: [Int8] = [
        /*  0 */ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        /* 16 */ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        /* 32 */ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        /* 48 */ 15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        /* 64 */ -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        /* 80 */  1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        /* 96 */ -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        /*112 */  1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    ]

    public init() {}

    // MARK: - Polymod

    /// Find the polymod of `values` as 30-bit integer, per Bech32 spec.
    private func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ UInt32(v)
            for i in 0..<5 {
                let bit = (top >> i) & 1
                if bit != 0 {
                    chk ^= gen[Int(i)]
                }
            }
        }
        return chk
    }

    // MARK: - HRP Expand

    /// Expand an HRP for use in checksum computation.
    /// In the original code, we used `hrp.data(using: .utf8)`.
    /// Here, we just convert the string to `[UInt8]` and build the array.
    private func expandHrp(_ hrp: String) -> [UInt8] {
        let hrpBytes = Array(hrp.utf8)
        // we want hrpBytes.count*2 + 1 bytes
        // first half: each byte >> 5
        // middle: 0
        // second half: each byte & 0x1f
        var result = [UInt8](repeating: 0, count: hrpBytes.count * 2 + 1)

        for i in 0..<hrpBytes.count {
            result[i] = hrpBytes[i] >> 5
        }
        result[hrpBytes.count] = 0
        for i in 0..<hrpBytes.count {
            result[hrpBytes.count + 1 + i] = hrpBytes[i] & 0x1f
        }
        return result
    }

    // MARK: - Checksum

    /// Verify the existing checksum.
    private func verifyChecksum(hrp: String, checksum: [UInt8]) -> Bool {
        var data = expandHrp(hrp)
        data.append(contentsOf: checksum)
        return polymod(data) == 1
    }

    /// Create a 6-byte checksum for the given HRP + data.
    private func createChecksum(hrp: String, values: [UInt8]) -> [UInt8] {
        var enc = expandHrp(hrp)
        enc.append(contentsOf: values)
        // append 6 zero words
        enc.append(contentsOf: [UInt8](repeating: 0, count: 6))
        let mod = polymod(enc) ^ 1
        var ret = [UInt8](repeating: 0, count: 6)
        for i in 0..<6 {
            let shift = 5 * (5 - i)
            ret[i] = UInt8((mod >> shift) & 0x1f)
        }
        return ret
    }

    // MARK: - Encoding

    /// Encodes the given HRP and data part into a Bech32 string
    /// Equivalent to `encode_bech32`.
    public func encode(_ hrp: String, values: [UInt8]) -> String {
        // 1) create the 6-byte checksum
        let checksum = createChecksum(hrp: hrp, values: values)

        // 2) combine data + checksum
        var combined = values
        combined.append(contentsOf: checksum)

        // 3) build final string: "<hrp>1<encoded data>"
        // We'll do it manually in ASCII form:
        //   - hrp's utf8
        //   - '1'
        //   - each data value -> encCharset
        let hrpBytes = Array(hrp.utf8)

        // allocate the final array:
        //   hrpBytes.count + 1 (for '1') + combined.count
        var output = [UInt8]()
        output.reserveCapacity(hrpBytes.count + 1 + combined.count)

        // add the HRP
        output.append(contentsOf: hrpBytes)
        // add the delimiter '1' (0x31)
        output.append(0x31)

        // encode data
        for v in combined {
            output.append(encCharset[Int(v)])
        }

        // convert [UInt8] -> String (UTF-8)
        // This is pure Swift stdlib in Swift 5:
        return String(decoding: output, as: UTF8.self)
    }

    // MARK: - Decoding

    /// Find the last index of `delimiter` in `array`.
    /// We can't use Foundation's `range(of:options:)`.
    private func lastIndexOf(_ array: [UInt8], delimiter: UInt8) -> Int? {
        // search from the end
        for i in (0..<array.count).reversed() {
            if array[i] == delimiter {
                return i
            }
        }
        return nil
    }

    /// Checks if a given byte is a valid 'printable range' for Bech32 (ASCII 33..126).
    private func isPrintableASCII(_ c: UInt8) -> Bool {
        return c >= 33 && c <= 126
    }

    /// Decode a Bech32 string, returning `(hrp, dataWithoutChecksum)`
    public func decode(_ str: String) throws -> (hrp: String, checksum: [UInt8]) {
        // Convert String -> [UInt8] (UTF-8)
        let strBytes = Array(str.utf8)

        // 1) length checks
        if strBytes.count > 90 {
            throw DecodingError.stringLengthExceeded
        }

        // 2) check for mixed-case or non-printable
        var lowerFound = false
        var upperFound = false
        for b in strBytes {
            if !isPrintableASCII(b) {
                throw DecodingError.nonPrintableCharacter
            }
            // 'a'..'z' => ASCII 97..122
            if b >= 97 && b <= 122 {
                lowerFound = true
            }
            // 'A'..'Z' => ASCII 65..90
            if b >= 65 && b <= 90 {
                upperFound = true
            }
        }
        if lowerFound && upperFound {
            throw DecodingError.invalidCase
        }

        // 3) find the delimiter '1' from the end
        guard let pos = lastIndexOf(strBytes, delimiter: checksumMarker) else {
            throw DecodingError.noChecksumMarker
        }

        // 4) minimal HRP size of 1
        if pos < 1 {
            throw DecodingError.incorrectHrpSize
        }
        // also the data part must be at least 6 + 1 in length for the 6-byte checksum
        // so pos + 7 <= strBytes.count
        if pos + 7 > strBytes.count {
            throw DecodingError.incorrectChecksumSize
        }

        let hrpArray = Array(strBytes[0..<pos])
        // Data part size (excluding the '1')
        let dataPartSize = strBytes.count - 1 - pos

        // decode the data part into [UInt8] of "5-bit words"
        var values = [UInt8](repeating: 0, count: dataPartSize)
        for i in 0..<dataPartSize {
            let c = strBytes[pos + 1 + i]
            // if there's uppercase, convert to lowercase for decoding
            // or we can simply handle uppercase by offset. But the original table
            // expects ASCII a-z plus digits, so let's forcibly convert uppercase to lowercase if needed:
            let c2 = (c >= 65 && c <= 90) ? c + 32 : c  // manual to-lower
            let idx = Int(c2)
            // we must ensure idx < decCharset.count (128)
            if idx < 0 || idx >= decCharset.count {
                throw DecodingError.invalidCharacter
            }
            let decVal = decCharset[idx]
            if decVal < 0 {
                throw DecodingError.invalidCharacter
            }
            values[i] = UInt8(decVal)
        }

        // convert HRP array to lowercase if needed
        let hrpLowered = hrpArray.map { (c: UInt8) -> UInt8 in
            // ASCII uppercase => turn to lowercase
            if c >= 65 && c <= 90 {
                return c + 32
            }
            return c
        }
        // build hrp string
        let hrpString = String(decoding: hrpLowered, as: UTF8.self)

        // 5) verify the checksum
        if !verifyChecksum(hrp: hrpString, checksum: values) {
            throw DecodingError.checksumMismatch
        }

        // The returned data is everything except the last 6 bytes of the data part
        let payloadSize = dataPartSize - 6
        let payload = Array(values[..<payloadSize])

        return (hrpString, payload)
    }
}

extension Bech32 {
    public enum DecodingError: Error {
        case nonUTF8String
        case nonPrintableCharacter
        case invalidCase
        case noChecksumMarker
        case incorrectHrpSize
        case incorrectChecksumSize
        case stringLengthExceeded
        
        case invalidCharacter
        case checksumMismatch
        
        public var errorDescription: String? {
            switch self {
            case .checksumMismatch:
                return "Checksum doesn't match"
            case .incorrectChecksumSize:
                return "Checksum size too low"
            case .incorrectHrpSize:
                return "Human-readable-part is too small or empty"
            case .invalidCase:
                return "String contains mixed case characters"
            case .invalidCharacter:
                return "Invalid character met on decoding"
            case .noChecksumMarker:
                return "Checksum delimiter not found"
            case .nonPrintableCharacter:
                return "Non printable character in input string"
            case .nonUTF8String:
                return "String cannot be decoded by utf8 decoder"
            case .stringLengthExceeded:
                return "Input string is too long"
            }
        }
    }
}
