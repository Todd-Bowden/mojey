/*****************************************************************
|
|   Secure Key Box API
|
|   $Id: SkbSecureKeyBox.h 660 2019-03-12 15:11:07Z kstraupe $
|   Original author:  Gilles Boccon-Gibod
|
|   This software is provided to you pursuant to your agreement
|   with Intertrust Technologies Corporation ("Intertrust").
|   This software may be used only in accordance with the terms
|   of the agreement.
|
|   Copyright (c) 2005-2019, Intertrust Technologies Corporation. All rights reserved.
|
****************************************************************/
/**
* @file
* @brief Secure Key Box
*/

/** @mainpage SKB API
 *
 * @section intro_sec Introduction
 *
 * The SKB (Secure Key Box) API provides a simple interface to a code
 * module responsible for the handling of secret data, such as
 * cryptographic keys. It enables the use of secret data without exposing
 * this sensitive information to the calling application.
 *
 * The processing environment for a device is considered to be divided
 * into two domains: a secure domain in which all handling of secrets
 * is done, and an open domain. The SKB API is the boundary between those
 * domains.
 *
 * Code executing in the open domain (for example, an application running
 * on a general-purpose CPU) is often vulnerable to attacks, so it is risky
 * for it to access secret data in the clear. With the SKB API, such code
 * never needs to directly access secret data. Instead, the SKB API
 * implementation, executing in a security processor or otherwise secure
 * environment, can be responsible for all secrets. Code in the open domain
 * can simply invoke SKB API interfaces to ask the code executing in the
 * secure domain to manage secret data and perform operations on it.
 *
 * @section algorithms Cryptographic Algorithms
 *
 * The SKB API exposes common cryptographic methods to encrypt/decrypt,
 * sign/verify, and digest data (possibly including secret data). The SKB
 * implementation supports the following cryptographic algorithms:
 *
 *    - RSA 1.5 encryption/decryption, sign/verify
 *    - RSA OAEP encryption/decryption
 *    - AES 128-bit encryption/decryption in ECB, CBC, or CTR mode
 *    - SHA-1, and SHA-256 digests
 *    - HMAC signatures
 *
 * @section other_operations Other Operations
 *
 * The API also provides a mechanism to unwrap a cryptographically wrapped
 * key (a key encrypted with another key) and then to use the key in
 * cryptographic operations.
 *
 * Applications can also ask the API to export secret data, that is,
 * provide a protected form of the secret data that the caller can store
 * in non-secure persistent storage. When needed later, the data can be
 * returned to its original form (in the secret domain) so that it can
 * be used in further operations.
 *
 * @section getting_started Getting Started
 *
 * The interface to the SKB is a C interface, composed of a number of object
 * classes. Even though the interface is an ANSI C interface, it adopts an
 * object-oriented style. The header file declares object classes. An object
 * class defines the functional interface to the class (a set of methods).
 * Each method of a class interface is a function whose first argument is a
 * reference to an instance of the same class. The data type that represents
 * references to object instances is a pointer to an opaque C struct. It may
 * be considered as analogous to a pointer to a C++ object.
 *
 * @section example Example
 *
 * A concrete example is that for the class named SKB_Cipher, the data type
 * SKB_Cipher is the name of a C struct. The function name for one of the
 * methods of SKB_Cipher is SKB_Cipher_ProcessBuffer(), and the function
 * takes an SKB_Cipher* as its first parameter.
 *
 * @section instances Obtaining Class Instances
 *
 * An instance of a class is obtained by declaring a pointer to an object
 * for the class and passing the address of that pointer to a particular
 * function. The function creates the instance and sets the pointer to refer
 * to it.
 *
 * For example, the first object that you need to create when you are going
 * to use the SKB API is an SKB_Engine. An SKB_Engine object represents an
 * instance of an engine that can manage and operate on secret data. An
 * SKB_Engine instance is obtained by calling SKB_Engine_GetInstance(), which
 * is declared as follows:
 *
 * <pre>
 *   SKB_Result SKB_Engine_GetInstance(SKB_Engine** engine);</pre>
 * As you can see, the parameter is the address of an SKB_Engine pointer.
 * This  method creates an SKB_Engine instance, and sets the pointer to refer to
 * the new instance. Here is a sample call:
 * <pre>
 *   SKB_Engine* engine = NULL;
 *   SKB_Result result;
 *   result = SKB_Engine_GetInstance(&engine);</pre>
 * @section method_calls Making Method Calls
 *
 * In the C object-oriented style for the API, a call to a method of a
 * particular instance is done by calling a function and passing a pointer to
 * the instance as the first parameter.
 *
 * For example, once an SKB_Engine instance is created, as shown in the previous
 * section, all the SKB_Engine methods can be called to operate on that instance.
 * One such method is the SKB_Engine_GetInfo() method, which is used to obtain
 * information about the engine (version numbers, properties, and so on). This
 * method is declared as follows:
 *
 * <pre>
 *     SKB_Result SKB_Engine_GetInfo(const SKB_Engine* self, SKB_EngineInfo* info);</pre>
 *
 * This method stores the engine information in the SKB_EngineInfo structure
 * pointed to by the info parameter. Assuming engine is the pointer previously
 * set by SKB_Engine_GetInstance() to refer to the SKB_Engine instance it created,
 * SKB_Engine_GetInfo() can be invoked by the following:
 *
 * <pre>
 *     SKB_Result result;
 *     SKB_EngineInfo engineInfo;
 *     result = SKB_Engine_GetInfo(engine, &engineInfo);</pre>
 *
 * @section header_file Header File
 *
 * The file SkbSecureKeyBox.h contains the entire SKB API interface.
 *
 * @section classes Main Classes
 *
 * As mentioned above, the first object you should instantiate is an SKB_Engine.
 * All other class instances are instantiated by calling SKB_Engine methods.
 *
 * The primary abstractions exposed by the API are the SKB_SecureData,
 * SKB_Transform, and SKB_Cipher classes.
 *
 * The SKB_SecureData object represents secret data. It allows an application
 * to refer to and operate on data managed by the SKB. Some SKB_SecureData
 * objects are named, so that a calling application can locate a specific
 * secret within the SKB. For example, each device is considered to have a
 * well-guarded secret device key. It is a key that is sufficiently protected
 * so as to act as a root of trust used to enable the secure marshaling of
 * other keys and credentials into the Secure Key Box. An application can
 * ask the SKB_Engine to create an SKB_SecureData object referencing the
 * device key. It asks for this key by name (TBD).
 *
 * An SKB_SecureData object is created for each (usually secret) data item
 * to be operated on by the SKB. To create an SKB_SecureData object, call an
 * appropriate SKB_Engine method. For example, SKB_Engine_CreateDataFromWrapped()
 * creates an SKB_SecureData object representing the data resulting from
 * unwrapping (decrypting) specified wrapped data.
 *
 * An SKB_Transform is used to perform operations on data, such as digest
 * calculations. It returns the output to the caller. Due to the nature of
 * the transforms available, the output does not expose any secret data.
 * You create an SKB_Transform by calling the SKB_Engine_CreateTransform() method.
 *
 * An SKB_Cipher object encapsulates the attributes and parameters necessary to
 * perform cryptographic operations on SKB_SecureData objects. You create an
 * SKB_Cipher by calling the SKB_Engine_CreateCipher() method.
 *
 * @section return_values Method Return Values
 *
 * As you can see from the examples above, most SKB API methods return an
 * SKB_Result.
 *
 * An SKB_Result is an int, and its possible values are defined in
 * SkbSecureKeyBox.h. When a method call succeeds, the return value is
 * SKB_SUCCESS. Otherwise, it is a negative number.
 *
 * @section conventions Conventions for Functions Returning Output in Variable-length Buffer
 *
 * A number of the functions defined in the SKB API return a variable amount of output
 * in a buffer provided by the caller. The output is returned in a variable-length
 * application-supplied buffer. An example of a function of this sort is
 * SKB_Transform_GetOutput().
 *
 * These functions have some common calling conventions, which we describe here. Two of
 * the arguments to the function are a pointer to the output buffer (say 'output')
 * and a pointer to a location which will hold the length of the output produced
 * (say 'output_size'). There are two ways for an application to call such a function:
 *
 * * If output is NULL, then all that the function does is return (in *output_size)
 * a number of bytes which would suffice to hold the output produced by the function.
 * This number may somewhat exceed the precise number of bytes needed, but should not
 * exceed it by a large amount. SKB_SUCCESS is returned by the function.
 *
 * * If output is not NULL, then *output_size must contain the size in bytes
 * of the buffer pointed to by 'output'. If that buffer is large enough to hold
 * the output produced by the function, then that output is placed there, and
 * SKB_SUCCESS is returned by the function. If the buffer is not large enough,
 * then SKB_ERROR_BUFFER_TOO_SMALL is returned. In either case, *output_size is
 * set to hold the exact number of bytes of output produced by the function.
 *
 * @section thread_model Thread Model
 *
 * An engine (SKB_Engine_GetInstance) and any object or data obtained directly or
 * indirectly from this engine may only be accessed from the same thread
 * as the one on which the engine was obtained. Multiple threads can each
 * use different engines, but engines cannot be passed or shared between
 * threads. If an instance of an SKB_SecureData object needs to be transfered
 * from one engine to another, the SKB_SecureData_Export() method can be used
 * with the 'target' parameter set to SKB_EXPORT_TARGET_CROSS_ENGINE, and
 * the exported buffer can be loaded in a different engine by calling
 * SKB_Engine_CreateDataFromExported().
 */

#ifndef _SKB_SECURE_KEY_BOX_H_
#define _SKB_SECURE_KEY_BOX_H_

/*----------------------------------------------------------------------
|       support for shared object symbols
+---------------------------------------------------------------------*/
#ifndef SKB_NO_EXPORT
#if __GNUC__ >= 4
#define SKB_EXPORT __attribute__ ((visibility ("default")))
#else
#define SKB_EXPORT
#endif
#else
#define SKB_EXPORT
#endif /* SKB_NO_EXPORT */

 /*----------------------------------------------------------------------
|   constants
+---------------------------------------------------------------------*/
/* Current SKB engine version numbers. */
#define SKB_API_VERSION_MAJOR    5
#define SKB_API_VERSION_MINOR    18
#define SKB_API_VERSION_REVISION 1
#define SKB_API_VERSION_STRING   "5.18.1"

/* SKB_Result values */
#define SKB_SUCCESS 0x2BD2F164
#define SKB_FAILURE 0x634D3E48

#define SKB_ERROR_INTERNAL           0x64F772B6
#define SKB_ERROR_INVALID_PARAMETERS 0x15133AFA
#define SKB_ERROR_NOT_SUPPORTED      0x117450F4
#define SKB_ERROR_OUT_OF_RESOURCES   0x07769E67
#define SKB_ERROR_BUFFER_TOO_SMALL   0x77A027D3
#define SKB_ERROR_INVALID_FORMAT     0x5F7DF2C9
#define SKB_ERROR_ILLEGAL_OPERATION  0x1BE8ABE4
#define SKB_ERROR_INVALID_STATE      0x2D49EC7A
#define SKB_ERROR_OUT_OF_RANGE       0x5596458F

/* SKB_Result values specific to whiteCryption Secure Key Box */
#define SKB_ERROR_EVALUATION_EXPIRED            0x6D7CB8C3
#define SKB_ERROR_KEY_CACHE_FAILED              0x0445A82E
#define SKB_ERROR_INVALID_EXPORT_KEY_VERSION    0x19DAFB62
#define SKB_ERROR_INVALID_EXPORT_KEY            0x11A5C9B1
#define SKB_ERROR_AUTHENTICATION_FAILURE        0x4EAC5FAF

/* Values for the 'flags' parameter of SKB_Engine_CreateCipher. */
/**
 * Set when the cipher is intended to be used with high throughput
 * (for example, media content decryption)
 */
#define SKB_CIPHER_FLAG_HIGH_SPEED 1

/* Values for the 'derivation_flags' member of SKB_RawBytesFromEccPrivateDerivationParameters. */
/**
 * Set when the output is expected to be in big endian encoding.
 */
#define SKB_DERIVATION_FLAG_OUTPUT_IN_BIG_ENDIAN 1

/* Values for the 'secret_size' parameter of SKB_KeyAgreement_ComputeSecret. */
/**
 * Set when the resulting key is intended to have the biggest possible size.
 */
#define SKB_KEY_AGREEMENT_MAXIMAL_SECRET_SIZE 0

/*----------------------------------------------------------------------
|   objects types
+---------------------------------------------------------------------*/
/** @defgroup SKB_SecureData SKB_SecureData Class
 * @{
 */

/**
 * An SKB_SecureData object represents secret data that cannot be accessed
 * directly by the caller. Secret data is typed; it can represent cipher
 * keys or arbitrary byte sequences.
 */
typedef struct SKB_SecureData SKB_SecureData;

/** @} */

/** @defgroup SKB_Transform SKB_Transform Class
 * @{
 */

/**
 * An SKB_Transform object represents a data transform. The purpose of such a
 * transform is to be able to transform data supplied by the caller, as well as
 * secret data, and return to the caller the output of the transform, which,
 * due to the nature of the transforms available (such as digests), does not
 * reveal any of the secret data used as input to the transform.
 */
typedef struct SKB_Transform SKB_Transform;

/** @} */

/** @defgroup SKB_Cipher SKB_Cipher Class
 * @{
 */

/**
 * An SKB_Cipher object can encrypt or decrypt data supplied by the caller.
 */
typedef struct SKB_Cipher SKB_Cipher;

/** @} */

/** @defgroup SKB_Engine SKB_Engine Class
 * @{
 */

/**
 * An SKB_Engine object represents an instance of an engine that
 * can manage and operate on secret data that cannot be accessed
 * by the caller.
 */
typedef struct SKB_Engine SKB_Engine;

/** @} */

/** @defgroup SKB_ECDH SKB_ECDH Class
 * @{
 */

/**
 * An SKB_KeyAgreement object can create new public/private keys
 * for supported key agreement protocol, and can also create
 * common SKB_SecureData object from public key of other party.
 */
typedef struct SKB_KeyAgreement SKB_KeyAgreement;

/** @} */

/*----------------------------------------------------------------------
|   other types and enums
+---------------------------------------------------------------------*/
/* Basic data types. */
typedef int SKB_Result;
typedef unsigned char SKB_Byte;
typedef unsigned int SKB_Size;

/**
 * Engine property.
 */
typedef struct {
    const char* name;
    const char* value;
} SKB_EngineProperty;

/**
 * Information about an SKB_Engine.
 */
typedef struct {
    struct {
        unsigned int major;
        unsigned int minor;
        unsigned int revision;
    } api_version;
    unsigned int        flags;
    unsigned int        property_count;
    SKB_EngineProperty* properties; /**< array of properties */
} SKB_EngineInfo;

/**
 * Possible types of data in the value encapsulated by an SKB_SecureData object.
 */
typedef enum {
    SKB_DATA_TYPE_BYTES = 0x73FE7340, /**< can be used as a symmetric key */
    SKB_DATA_TYPE_UNWRAP_BYTES = 0x3D63FCFB, /**< can be used as a symmetric key */
    SKB_DATA_TYPE_RSA_PRIVATE_KEY = 0x1E91746D,
    SKB_DATA_TYPE_ECC_PRIVATE_KEY = 0x56661AA8,
    SKB_DATA_TYPE_DSA_PRIVATE_KEY = 0x562BEB48,
    SKB_DATA_TYPE_RSA_PUBLIC_KEY_CONTEXT = 0x075CFCF3,
    SKB_DATA_TYPE_FORCE_32 = 0x7fffffff
} SKB_DataType;

/**
 * Information about an SKB_SecureData.
 */
typedef struct {
    SKB_DataType type;   /**< Data type  */
    SKB_Size     size;   /**< Data size, in bytes (or 0 if not available)
                             For data of type SKB_DATA_TYPE_RSA_PRIVATE_KEY,
                             this value is the modulus (in bytes) */
} SKB_DataInfo;

/**
 * Digest algorithm types.
 */
typedef enum {
    SKB_DIGEST_ALGORITHM_SHA1 = 0x7DFB1E6E,
    SKB_DIGEST_ALGORITHM_SHA224 = 0x1AA1C64B,
    SKB_DIGEST_ALGORITHM_SHA256 = 0x66BB991C,
    SKB_DIGEST_ALGORITHM_SHA384 = 0x082632B6,
    SKB_DIGEST_ALGORITHM_SHA512 = 0x076908BB,
    SKB_DIGEST_ALGORITHM_MD5 = 0x4713D3DD,
    SKB_DIGEST_ALGORITHM_FORCE_32 = 0x7fffffff
} SKB_DigestAlgorithm;

/**
 * Cipher algorithm types.
 */
typedef enum {
    SKB_CIPHER_ALGORITHM_NULL = 0x2282C58C,
    SKB_CIPHER_ALGORITHM_AES_128_ECB = 0x520A8B5C,
    SKB_CIPHER_ALGORITHM_AES_128_CBC = 0x4C09EA36,  /**< use xmlenc padding for unwrapping ( http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block ) unless explicitly switched off */
    SKB_CIPHER_ALGORITHM_AES_128_CTR = 0x6C6C67EE,
    SKB_CIPHER_ALGORITHM_AES_128_GCM = 0x1D3E32F4,
    SKB_CIPHER_ALGORITHM_AES_128_CCM = 0x10E455E1,
    SKB_CIPHER_ALGORITHM_RSA_1_5 = 0x7759CA00,
    SKB_CIPHER_ALGORITHM_RSA_OAEP = 0x26A0235F, /* using SHA-1 hash function */
    SKB_CIPHER_ALGORITHM_RSA_OAEP_SHA224 = 0x4480F272,
    SKB_CIPHER_ALGORITHM_RSA_OAEP_SHA256 = 0x1F7CCDA1,
    SKB_CIPHER_ALGORITHM_RSA_OAEP_SHA384 = 0x0F10D3A0,
    SKB_CIPHER_ALGORITHM_RSA_OAEP_SHA512 = 0x7DA9D48B,
    SKB_CIPHER_ALGORITHM_RSA_OAEP_MD5 = 0x6BE8DD62,
    SKB_CIPHER_ALGORITHM_ECC_ELGAMAL = 0x7B56793D,
    SKB_CIPHER_ALGORITHM_AES_192_ECB = 0x0E2A1F73,
    SKB_CIPHER_ALGORITHM_AES_192_CBC = 0x17055C18,
    SKB_CIPHER_ALGORITHM_AES_192_CTR = 0x5CD046BB,
    SKB_CIPHER_ALGORITHM_AES_192_GCM = 0x5292D58C,
    SKB_CIPHER_ALGORITHM_AES_192_CCM = 0x6FDE2297,
    SKB_CIPHER_ALGORITHM_AES_256_ECB = 0x7C8E6A54,
    SKB_CIPHER_ALGORITHM_AES_256_CBC = 0x05105F8D,
    SKB_CIPHER_ALGORITHM_AES_256_CTR = 0x5C6A3282,
    SKB_CIPHER_ALGORITHM_AES_256_GCM = 0x07223BDB,
    SKB_CIPHER_ALGORITHM_AES_256_CCM = 0x193204B3,
    SKB_CIPHER_ALGORITHM_DES_ECB = 0x7FEE7553,
    SKB_CIPHER_ALGORITHM_DES_CBC = 0x1DC1B654,
    SKB_CIPHER_ALGORITHM_TRIPLE_DES_ECB = 0x619A5EF1,
    SKB_CIPHER_ALGORITHM_TRIPLE_DES_CBC = 0x044E87AF,
    SKB_CIPHER_ALGORITHM_RSA = 0x75A78F30,
    SKB_CIPHER_ALGORITHM_NIST_AES = 0x54B36EF0,
    SKB_CIPHER_ALGORITHM_AES_CMLA = 0x33D3A2D8,
    SKB_CIPHER_ALGORITHM_RSA_CMLA = 0x7573F744,
    SKB_CIPHER_ALGORITHM_XOR = 0x52B2B4A7,
    SKB_CIPHER_ALGORITHM_SPECK_64_128_ECB = 0x2331F2F9,
    SKB_CIPHER_ALGORITHM_SPECK_64_128_CBC = 0x35D40975,
    SKB_CIPHER_ALGORITHM_SPECK_64_128_CTR = 0x013620F5,
    SKB_CIPHER_ALGORITHM_FORCE_32 = 0x7fffffff
} SKB_CipherAlgorithm;

/**
 * Cipher parameters
 */
typedef struct {
    /**
     * size in bytes of the counter (4, 8, 16)
     * This value is purely indicative, and can be used as
     * an optimization hint: it indicates that the counter
     * values will be such that only the rightmost counter_size
     * bytes in the IV will ever change, the others won't.
     * An implementation may ignore that parameter.
     */
    SKB_Size counter_size;
} SKB_CtrModeCipherParameters;

/**
 * Types of possible padding for wrapping/unwrapping using block ciphers in CBC mode.
 */
typedef enum {
    SKB_CBC_PADDING_TYPE_NONE = 0x60D08725,
    SKB_CBC_PADDING_TYPE_XMLENC = 0x5373D3B6,
    SKB_CBC_PADDING_TYPE_FORCE_32 = 0x7fffffff
} SKB_CbcPadding;

/**
 * Tells the AES-CBC algorithm whether to use padding or not during unwrapping.
 */
typedef struct {
    SKB_CbcPadding padding; 
} SKB_AesUnwrapParameters;

/**
* GCM mode parameters.
*/
typedef struct {
    const SKB_Byte* additional_authenticated_data;
    SKB_Size  additional_authenticated_data_size;
    const SKB_Byte* initialization_vector;
    SKB_Size  initialization_vector_size;
    const SKB_Byte* authentication_tag;
    SKB_Size  authentication_tag_size;
} SKB_GcmUnwrapParameters;

typedef struct {
    const SKB_Byte* initialization_vector;
    SKB_Size  initialization_vector_size;
} SKB_GcmCipherParameters;

typedef struct {
    SKB_Byte* authentication_tag;
    SKB_Size  authentication_tag_size;
} SKB_AuthenticationParameters;

/**
 * Signature algorithm types.
 */
typedef enum {
    SKB_SIGNATURE_ALGORITHM_AES_128_CMAC = 0x65C31413,
    SKB_SIGNATURE_ALGORITHM_AES_192_CMAC = 0x2E0DF2E8,
    SKB_SIGNATURE_ALGORITHM_AES_256_CMAC = 0x0D9DDFC1,
    SKB_SIGNATURE_ALGORITHM_SPECK_64_128_CMAC = 0x2E8D742E,
    SKB_SIGNATURE_ALGORITHM_HMAC_SHA1 = 0x2898F626,
    SKB_SIGNATURE_ALGORITHM_HMAC_SHA224 = 0x107E2A28,
    SKB_SIGNATURE_ALGORITHM_HMAC_SHA256 = 0x213903C1,
    SKB_SIGNATURE_ALGORITHM_HMAC_SHA384 = 0x3CE75561,
    SKB_SIGNATURE_ALGORITHM_HMAC_SHA512 = 0x26F3CE17,
    SKB_SIGNATURE_ALGORITHM_HMAC_MD5 = 0x30B611AC,
    SKB_SIGNATURE_ALGORITHM_RSA = 0x5FAF97DD,                       /**< PKCS #1 block type 2. */
    SKB_SIGNATURE_ALGORITHM_DSA = 0x32346B53,
    SKB_SIGNATURE_ALGORITHM_ECDSA = 0x398D6D81,
    SKB_SIGNATURE_ALGORITHM_ECDSA_SHA1 = 0x373E83A9,
    SKB_SIGNATURE_ALGORITHM_ECDSA_SHA224 = 0x4A0A913D,
    SKB_SIGNATURE_ALGORITHM_ECDSA_SHA256 = 0x3C0B75D7,
    SKB_SIGNATURE_ALGORITHM_ECDSA_SHA384 = 0x35B5D5F7,
    SKB_SIGNATURE_ALGORITHM_ECDSA_SHA512 = 0x49D6A295,
    SKB_SIGNATURE_ALGORITHM_ECDSA_MD5 = 0x703D046E,
    SKB_SIGNATURE_ALGORITHM_RSA_MD5 = 0x673B4698,
    SKB_SIGNATURE_ALGORITHM_RSA_SHA1 = 0x24419A3C,
    SKB_SIGNATURE_ALGORITHM_RSA_SHA224 = 0x3E2D04A4,
    SKB_SIGNATURE_ALGORITHM_RSA_SHA256 = 0x5C7272C6,
    SKB_SIGNATURE_ALGORITHM_RSA_SHA384 = 0x5E4F9BE3,
    SKB_SIGNATURE_ALGORITHM_RSA_SHA512 = 0x2D2439BA,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_MD5 = 0x35AF4A98,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA1 = 0x2D44F448,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA224 = 0x696C9E56,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA256 = 0x39321A5B,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA384 = 0x27DEE4AC,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA512 = 0x09EACD25,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_MD5_EX = 0x65761082,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA1_EX = 0x321B5956,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA224_EX = 0x4186E01C,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA256_EX = 0x2BD6CC43,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA384_EX = 0x1037A071,
    SKB_SIGNATURE_ALGORITHM_RSA_PSS_SHA512_EX = 0x23B4DBA1,
    SKB_SIGNATURE_ALGORITHM_DES_RETAIL_MAC = 0x30A3D5EE,
    SKB_SIGNATURE_ALGORITHM_FORCE_32 = 0x7fffffff
} SKB_SignatureAlgorithm;

/**
 * Derivation Algorithms
 */
typedef enum {
    SKB_DERIVATION_ALGORITHM_SLICE = 0x77C27129,      /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_BLOCK_SLICE = 0x4FDB306A,      /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_BLOCK_CONCATENATE = 0x4C7DB858, /**< data type must be SKB_DATA_TYPE_BYTES or SKB_DATA_TYPE_UNWRAP_BYTES */
    SKB_DERIVATION_ALGORITHM_SELECT_BYTES = 0x4153888E, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_SHA_1 = 0x5DB9B45D,       /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_SHA_256 = 0x4C72EB0E,       /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_SHA_384 = 0x54469F94,       /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_REVERSE_BYTES = 0x139A7AF4, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_NIST_800_108_COUNTER_CMAC_AES128 = 0x7D298246, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_NIST_800_108_COUNTER_CMAC_AES128_L16BIT = 0x51FF014A, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_NIST_800_108_COUNTER_CMAC_SPECK_L16BITLE = 0x31441AF5, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_OMA_DRM_KDF2 = 0x3FD6E153, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_CIPHER = 0x7BB1F48A, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_RAW_BYTES_FROM_ECC_PRIVATE = 0x12D18C6A, /**< data type must be SKB_DATA_TYPE_ECC_PRIVATE_KEY */
    SKB_DERIVATION_ALGORITHM_CMLA_KDF = 0x6A095B26, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_SHA_AES = 0x6EBDD7B8, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_XOR = 0x489505DB, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_DOUBLE_AES_ENCRYPT = 0x025E59AA, /**< data type must be SKB_DATA_TYPE_UNWRAP_BYTES */
    SKB_DERIVATION_ALGORITHM_GET_RESTRICTED_USAGE_KEY = 0x56B1C2CD, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_AES_PLAIN_KEY_DECRYPT = 0x6AC26F14, /**< data type must be SKB_DATA_TYPE_UNWRAP_BYTES */
    SKB_DERIVATION_ALGORITHM_MIX_WITH_PLAIN_A = 0x68D2B59C, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_MIX_WITH_PLAIN_B = 0x5CBBADCA, /**< data type must be SKB_DATA_TYPE_BYTES */
    SKB_DERIVATION_ALGORITHM_FORCE_32 = 0x7fffffff
} SKB_DerivationAlgorithm;

/**
 * Indication as to whether an SKB_Cipher can be used for encryption or decryption.
 */
typedef enum {
    SKB_CIPHER_DIRECTION_ENCRYPT = 0x0CB1F623,
    SKB_CIPHER_DIRECTION_DECRYPT = 0x21E21BDC,
    SKB_CIPHER_DIRECTION_FORCE_32 = 0x7fffffff
} SKB_CipherDirection;

/**
 * Data formats.
 */
typedef enum {
    SKB_DATA_FORMAT_RAW = 0x045B0187,
    SKB_DATA_FORMAT_PKCS8 = 0x0F490AF1,
    SKB_DATA_FORMAT_PKCS1 = 0x34FD7BA4,
    SKB_DATA_FORMAT_ECC_BINARY = 0x0BD9303F,
    SKB_DATA_FORMAT_JSON = 0x01BE7ABC,
    SKB_DATA_FORMAT_CRT = 0x55320EB6,
    SKB_DATA_FORMAT_FORCE_32 = 0x7fffffff
} SKB_DataFormat;

/**
 * Different types of transforms.
 */
typedef enum {
    SKB_TRANSFORM_TYPE_DIGEST = 0x0EB33E49, /**< Compute a message digest. The transform parameter is a pointer to an SKB_DigestTransformParameters */
    SKB_TRANSFORM_TYPE_SIGN = 0x171E0988, /**< Compute a signature. The transform parameter is a pointer to an SKB_SignTransformParameters */

    /**
     * Verify a signature. The transform parameter is a pointer to an SKB_VerifyTransformParameters
     * The output of this transform is a single byte with the value 1 if the signature is verified,
     * or 0 if it is not
     */
    SKB_TRANSFORM_TYPE_VERIFY = 0x7CB1E6AB,

    SKB_TRANSFORM_TYPE_FORCE_32 = 0x7fffffff
} SKB_TransformType;

/**
 * Different types of byte selection
 */
typedef enum
{
    SKB_SELECT_BYTES_DERIVATION_ODD_BYTES = 0x62D437CF, /**< odd byte selection (indices: 0, 2, ..) */
    SKB_SELECT_BYTES_DERIVATION_EVEN_BYTES = 0x3F8D7FD1, /**< even byte selection (indices: 1, 3, ..) */
    SKB_SELECT_BYTES_DERIVATION_FORCE_32 = 0x7fffffff
} SKB_SelectBytesDerivationVariant;

/**
 * Structure defining parameters for a transform of type SKB_TRANSFORM_TYPE_DIGEST.
 */
typedef struct {
    SKB_DigestAlgorithm algorithm;
} SKB_DigestTransformParameters;

/**
 * Structure defining parameters for a transform of type SKB_TRANSFORM_TYPE_SIGN.
 */
typedef struct {
    SKB_SignatureAlgorithm  algorithm; /**< Signature algorithm. */
    const SKB_SecureData*   key;       /**< Signature key. This key must not be released before the transform object that uses it is released */
} SKB_SignTransformParameters;

/**
 * Structure defining parameters for a transform of type SKB_TRANSFORM_TYPE_SIGN, extended version.
 */
typedef struct {
    SKB_SignTransformParameters base;
    const void*                 extension; /**< Parameters for customizable signature algorithms */
} SKB_SignTransformParametersEx;

/**
 * Structure defining parameters for a transform of type SKB_TRANSFORM_TYPE_VERIFY.
 */
typedef struct {
    SKB_SignatureAlgorithm  algorithm;      /**< Signature algorithm. */
    const SKB_SecureData*   key;            /**< Signature key. This key must not be released before the transform object that uses it is released */
    const SKB_Byte*         signature;      /**< Signature to verify the data against */
    SKB_Size                signature_size; /**< Size of the signature */
} SKB_VerifyTransformParameters;

/**
 * Structure defining parameters for a derivation of type SKB_DERIVATION_ALGORITHM_CIPHER.
 */
typedef struct {
    SKB_CipherAlgorithm     cipher_algorithm;
    SKB_CipherDirection     cipher_direction;
    unsigned int            cipher_flags;
    const void*             cipher_parameters;
    const SKB_SecureData*   cipher_key;
    const SKB_Byte*         iv;
    SKB_Size                iv_size;
} SKB_CipherDerivationParameters;

/**
 * Structure defining parameters for a derivation of type SKB_DERIVATION_ALGORITHM_SHA_1.
 * If this parameter is NULL in the SKB_SecureData_Derive method, the default values
 * are 1 for round_count and 20 (size of SHA-1 digest) for output_size
 */
typedef struct {
    unsigned int round_count;
    unsigned int output_size;
} SKB_Sha1DerivationParameters;

/**
 * Structure defining parameters for a derivation of type SKB_DERIVATION_ALGORITHM_SHA_256.
 * If this parameter is NULL in the SKB_SecureData_Derive method, then the digest is updated
 * with only the secure data
 */
typedef struct {
    const SKB_Byte*         plain1;
    SKB_Size                plain1_size;
    const SKB_Byte*         plain2;
    SKB_Size                plain2_size;
} SKB_Sha256DerivationParameters;

/**
 * Structure defining parameters for derivations of type SKB_DERIVATION_ALGORITHM_SLICE and SKB_DERIVATION_ALGORITHM_BLOCK_SLICE
 */
typedef struct {
    unsigned int first;
    unsigned int size;
} SKB_SliceDerivationParameters;

/**
 * Structure defining parameters for a derivation of type SKB_DERIVATION_ALGORITHM_SELECT_BYTES
 */
typedef struct
{
    SKB_SelectBytesDerivationVariant variant;
    unsigned int output_size;
} SKB_SelectBytesDerivationParameters;

/**
 * Structure defining parameters for Nist 800-108 based derivation algorithms
 */
typedef struct {
    const SKB_Byte*         label;
    SKB_Size                label_size;
    const SKB_Byte*         context;
    SKB_Size                context_size;
    SKB_Size                output_size;
} SKB_Nist800108KdfDerivationParameters;

/**
 * SKB_Nist800108CounterCmacAes128Parameters parameters are deprecated and will be removed in future
 */
typedef SKB_Nist800108KdfDerivationParameters SKB_Nist800108CounterCmacAes128Parameters;

/**
 * Structure defining parameters for a derivation of type SKB_DERIVATION_ALGORITHM_OMA_DRM_KDF2
 */
typedef struct {
    const SKB_Byte* label;
    SKB_Size        label_size;
    SKB_Size        output_size;
} SKB_OmaDrmKdf2DerivationParameters;

/**
 * Structure defining parameters for a derivation of type SKB_DERIVATION_ALGORITHM_SHA_AES
 */

typedef struct {
    const SKB_SecureData* secure_p;
    const SKB_Byte*       plain_1;
    SKB_Size              plain_1_size;
    const SKB_Byte*       plain_2;
} SKB_ShaAesDerivationParameters;

/**
 * Structure defining parameters for derivation types which need secure and/or plain input parameters
 */

typedef struct {
    const SKB_SecureData* secure_input;
    const SKB_Byte*       plain_input;
    SKB_Size              plain_input_size;
} SKB_GenericDerivationParameters;

/**
 * Different types of possible targets for a secure data export (see SKB_SecureData_Export).
 */
typedef enum {
    /**
     * Export in cleartext form. No parameters.
     * NOTE: This type of export is normally only used in 'debug' or 'test'
     * implementations of SKB, and would be dissallowed in 'release' or 'production' implementations.
     */
    SKB_EXPORT_TARGET_CLEARTEXT = 0x7C92EBE1,

    /**
     * Export in a persistent form that can be reloaded after a reboot/reset. No parameters.
     */
    SKB_EXPORT_TARGET_PERSISTENT = 0x7E09BCEC,

    /**
     * Export in a form that can be loaded in a different engine, but not across reboot/reset. No parameters.
     */
    SKB_EXPORT_TARGET_CROSS_ENGINE = 0x5EBE3F0E,

    /**
     * Export to a custom form. The 'target_parameters' must point to an SKB_ExportCustomParameters structure.
     */
    SKB_EXPORT_TARGET_CUSTOM = 0x04615AE4,

    SKB_EXPORT_TARGET_FORCE_32 = 0x7fffffff
} SKB_ExportTarget;

/**
 * Custom parameters for an export with target SKB_EXPORT_TARGET_CUSTOM
 */
typedef struct {
    const char* uid;     /**< Unique identifier for the export format */
    const void* options; /**< Optional pointer to options for the export format */
} SKB_ExportCustomParameters;

/**
 * Different types of ECC curves
 */
typedef enum {
    SKB_ECC_CURVE_SECP_R1_160 = 0x0BDA5525,  /**< 160-bit prime curve recommended by SECG, SECP R1 */
    SKB_ECC_CURVE_NIST_192 = 0x7FEDB30A,     /**< 192-bit prime curve recommended by NIST (same as 192-bit SECG, SECP R1) */
    SKB_ECC_CURVE_NIST_224 = 0x58421C77,     /**< 224-bit prime curve recommended by NIST (same as 224-bit SECG, SECP R1) */
    SKB_ECC_CURVE_NIST_256 = 0x1D25CFD0,     /**< 256-bit prime curve recommended by NIST (same as 256-bit SECG, SECP R1) */
    SKB_ECC_CURVE_NIST_384 = 0x08A5D638,     /**< 384-bit prime curve recommended by NIST (same as 384-bit SECG, SECP R1) */
    SKB_ECC_CURVE_NIST_521 = 0x2E8268AC,     /**< 521-bit prime curve recommended by NIST (same as 521-bit SECG, SECP R1) */
    SKB_ECC_CURVE_CUSTOM = 0x76705BD7,        /**< Prime ECC curve with custom ecc curve parameters, defined in SKB_EccCurveParameters structure */
    SKB_ECC_CURVE_FORCE_32 = 0x7fffffff
} SKB_EccCurve;

/**
 * The protocols supported by SKB_KeyAgreement
 */
typedef enum {
    SKB_KEY_AGREEMENT_ALGORITHM_ECDH = 0x7AA26B5C, /**< ECDH with fixed or custom curve and ephemeral key */
    SKB_KEY_AGREEMENT_ALGORITHM_PRIME_DH = 0x177C7852, /**< Classical DH with static generator G and modulus P */
    SKB_KEY_AGREEMENT_ALGORITHM_ECDH_STATIC = 0x1E18D46F, /**< ECDH with fixed or custom curve and static private key */
    SKB_KEY_AGREEMENT_ALGORITHM_FORCE_32 = 0x7fffffff
} SKB_KeyAgreementAlgorithm;

typedef struct
{
    const SKB_Byte* context;
    SKB_Size context_size;
} SKB_PrimeDhParameters;

/**
 * ECC custom curve parameters. These should be generated using CustomEccTool
 */
typedef struct {
    SKB_Size prime_bit_length;    /**< bit-length of the ECC prime parameter */
    SKB_Size order_bit_length;    /**< bit-length of the ECC order parameter */
    SKB_Size ecc_instance_length; /**< ECC instance bit-length (264 or 528) */
    const SKB_Byte* context;      /**< ECC context */
    SKB_Size context_size;        /**< ECC context size */
} SKB_EccCurveParameters;

/**
 * The parameters that must be passed to ECC implementation (NOTE: do not use with SKB_KEY_AGREEMENT_ALGORITHM_ECDH_STATIC algorithm which requires SKB_EcdhParameters).
 */
typedef struct {
    SKB_EccCurve curve;
    const SKB_EccCurveParameters* curve_parameters;
    const unsigned int* random_value; /**< Random K value for ECDSA, see implementation details for format. If Null is passed, internal random generation will be used. */
} SKB_EccParameters;

/**
 * The parameters that must be passed to DSA implementation
 */
typedef struct {
    SKB_Size l_bit_length; /* L length in bits */
    SKB_Size n_bit_length; /* N length in bits */
    const SKB_Byte* p; /* pointer to byte array of L length / 8 */
    const SKB_Byte* q; /* pointer to byte array of N length / 8 */
    const SKB_Byte* g; /* pointer to byte array of L length / 8 */
} SKB_DsaParameters;

/**
 * The parameters that must be passed to RSA key generation
 */
typedef struct {
    SKB_Size n_bit_length; /* N length in bits */
    SKB_Size e; /* exponent */
} SKB_RsaParameters;

/**
 * The parameters that can be passed to RSA PSS signature generation.
 */
typedef struct {
    const SKB_Byte* salt; /**< Salt value for RSA PSS signature algorithm. If Null is passed (or the extension is not passed at all), will generate a random salt value of specified length. */
    SKB_Size salt_length; /**< 0 <= sLen <= hlen, where hlen is the length of the used hash function's output block. */
} SKB_RsaPssParameters;

/**
 * The parameters that can be passed to raw bytes secure data generation.
 */
typedef struct {
    SKB_Size byte_count;
} SKB_RawBytesParameters;

/**
 * The parameters that can be passed to wrap secure data with AES.
 */
typedef struct {
    const SKB_Byte* iv;
} SKB_AesWrapParameters;

/**
 * The parameters that may be passed when deriving raw bytes from private ECC key.
 */
typedef struct {
    unsigned int derivation_flags;
} SKB_RawBytesFromEccPrivateDerivationParameters;


/**
 * The parameters that must be passed to ECDH key agreement SKB_KEY_AGREEMENT_ALGORITHM_ECDH_STATIC algorithm.
 */
typedef struct {
    SKB_EccCurve curve;
    const SKB_EccCurveParameters* curve_parameters;
    const SKB_SecureData* private_key; /**< The static private key to be used in the ECDH algorithm */
} SKB_EcdhParameters;

/*----------------------------------------------------------------------
|   macros
+---------------------------------------------------------------------*/
#define SKB_SUCCEEDED(_result) ((_result)==SKB_SUCCESS)
#define SKB_FAILED(_result)    ((_result)!=SKB_SUCCESS)

/*----------------------------------------------------------------------
|   interfaces
+---------------------------------------------------------------------*/
#if defined(__cplusplus)
extern "C" {
#endif

/** @ingroup SKB_Engine
 * @{
 */

/**
 * Obtains an engine instance.
 * This instance must be released by calling SKB_Engine_Release when no
 * longer needed.
 *
 * @param engine Address of an SKB_Engine pointer that will be set to
 * point to the newly created SKB_Engine object.
 */
SKB_EXPORT SKB_Result
SKB_Engine_GetInstance(SKB_Engine** engine);

/**
 * Releases the specified SKB_Engine object.
 * An SKB_Engine object must be released after it is no longer needed,
 * by calling this method.
 * The object can no longer be used by the caller after this call returns.
 * All objects returned by this engine, such as SKB_SecureData,
 * SKB_Cipher, and SKB_Transform objects, must be released before
 * calling this method.
 *
 * @param self The SKB_Engine to release.
 */
SKB_EXPORT SKB_Result
SKB_Engine_Release(SKB_Engine* self);

/**
 * Sets device specific identification string.
 * This string changes how export functionality works.
 * Importing is possible only if the DeviceID is set to the same value
 * that was used when exporting.
 * Zero length id is an exception.
 * When exported using zero length id, the data is always importable,
 * regardless of current DeviceID setting.
 * The default value of the DeviceID is a zero length id.
 *
 * @param self The SKB_Engine instance.
 * @param id - a byte array containing device specific identificator.
 * @param size - number of bytes in id paramteter.
 *
 */
SKB_EXPORT SKB_Result
SKB_Engine_SetDeviceId(SKB_Engine* self, const SKB_Byte* id, SKB_Size size);

/**
 * Obtains information (version numbers, properties, and so on) about the engine.
 *
 * @param self The SKB_Engine whose information is obtained.
 * @param info Pointer to an SKB_EngineInfo structure that will be populated
 * with the engine information.
 */
SKB_EXPORT SKB_Result
SKB_Engine_GetInfo(const SKB_Engine* self, SKB_EngineInfo* info);

/**
 * Obtains an SKB_SecureData object representing
 * particular secret data that is specified by name.
 * Specific names to be used to reference certain data objects will be
 * documented in these comments.
 *
 * @param self The SKB_Engine that will create an SKB_SecureData representing
 * the specified data.
 * @param name The name of the data object to obtain.
 * @param data Address of an SKB_SecureData pointer that will be set to point
 * to a new SKB_SecureData object representing the specified secret data.
 * This object must be released by calling SKB_SecureData_Release when no
 * longer needed.
 *
 * @return SKB_SUCCESS if the data object was found, SKB_ERROR_NO_SUCH_ITEM if
 * no such data object exists, or another error code if the call could not be
 * completed successfully.
 */
SKB_EXPORT SKB_Result
SKB_Engine_GetDataByName(SKB_Engine* self, const char* name, SKB_SecureData** data);

/**
 * Creates an SKB_SecureData object representing the bytes obtained by "unwrapping"
 * (decrypting) a specified sequence of "wrapped" bytes, or an SKB_SecureData object
 * simply representing the specified bytes, if they are not wrapped.
 * Wrapped data is data that has been encrypted. Frequently, it is a key that has been
 * encrypted using another key.
 * You pass this method the bytes, and information about the data format and
 * what type of data the bytes represent.
 * If the 'wrapped' parameter contains bytes that were previously wrapped, you also
 * pass a pointer to an SKB_SecureData representing the key that was used to encrypt
 * the data, and information about the cipher algorithm used, as well as any
 * parameters used by the algorithm.
 * If 'wrapped' contains bytes that are NOT wrapped,
 * wrapping_algorithm should be SKB_CIPHER_ALGORITHM_NULL, and
 * wrapping_parameters and unwrapping_key should both be NULL.
 *
 * @param self The SKB_Engine responsible for creating the SKB_SecureData.
 * @param wrapped The bytes to be optionally unwrapped (if they were previously
 *   wrapped, as determined by the wrapping_algorithm value) and then represented by
 *   a new SKB_SecureData.
 * @param wrapped_size The number of bytes in the 'wrapped' parameter.
 * @param wrapped_type The data type to be used for the SKB_SecureData created by
 *   this method.
 * @param wrapped_format The data format to be used for the SKB_SecureData created by
 *   this method.
 * @param wrapping_algorithm The cryptographic algorithm that was used to encrypt
 *   the wrapped bytes (SKB_CIPHER_ALGORITHM_NULL if the bytes are not encrypted).
 * @param wrapping_parameters Parameters for the algorithm (NULL if the bytes are
 *   not encrypted).
 * @param unwrapping_key Pointer to an SKB_SecureData object representing the key
 *   needed to decrypt the data (NULL if the bytes are not encrypted).
 * @param data Address of an SKB_SecureData pointer that will be set to point
 *   to a new SKB_SecureData object representing either the bytes specified in
 *   the 'wrapped' parameter (if they are not wrapped) or the result of unwrapping
 *   the specified wrapped bytes. This object must be released by calling
 *   SKB_SecureData_Release when no longer needed.
 */
SKB_EXPORT SKB_Result
SKB_Engine_CreateDataFromWrapped(SKB_Engine*           self,
                                 const SKB_Byte*       wrapped,
                                 SKB_Size              wrapped_size,
                                 SKB_DataType          wrapped_type,
                                 SKB_DataFormat        wrapped_format,
                                 SKB_CipherAlgorithm   wrapping_algorithm,
                                 const void*           wrapping_parameters,
                                 const SKB_SecureData* unwrapping_key,
                                 SKB_SecureData**      data);

/**
 * Creates an SKB_SecureData object representing the bytes obtained by "importing"
 * specified previously "exported" secret data. Secret data is exported (see
 * SKB_SecureData_Export) when a client wants to store it for future use. Clients
 * are not allowed to obtain the secret data bytes in the clear, so exporting
 * the bytes results in the client receiving a serialized and encrypted form
 * of the secret data. Later, when the client wants operations to be done
 * on the secret data, it calls this SKB_Engine_CreateDataFromExported method to
 * decrypt and deserialize the exported data and create an SKB_SecureData
 * representing it.
 *
 * @param self The SKB_Engine responsible for creating the SKB_SecureData.
 * @param exported The previously exported bytes.
 * @param exported_size The number of bytes in the 'exported' parameter.
 * @param data Address of an SKB_SecureData pointer that will be set to point
 *   to a new SKB_SecureData object representing the result of decrypting and
 *   deserializing the exported bytes. This object must be released by
 *   calling SKB_SecureData_Release when no longer needed.
 */
SKB_EXPORT SKB_Result
SKB_Engine_CreateDataFromExported(SKB_Engine*      self,
                                  const SKB_Byte*  exported,
                                  SKB_Size         exported_size,
                                  SKB_SecureData** data);

/**
 * Generates random SKB_SecureData object with the specified type and parameters.
 *
 * @param self The SKB_Engine responsible for creating the SKB_SecureData.
 * @param data_type The data type to generate.
 * @param generate_parameters Any parameters required by the generation.
 * @param data Address of an SKB_SecureData pointer that will be set
 *   to point to the newly created SKB_SecureData object.
 *   This object must be released by calling SKB_SecureData_Release when no
 *   longer needed. Generation will use the system random source -
 *   either /dev/random device or CryptoAPI.
  */
SKB_EXPORT SKB_Result
SKB_Engine_GenerateSecureData(SKB_Engine*      self,
                              SKB_DataType     data_type,
                              const void*      generate_parameters,
                              SKB_SecureData** data);

/**
 * Creates an SKB_Transform object with the specified type and parameters.
 *
 * @param self The SKB_Engine responsible for creating the SKB_Transform.
 * @param transform_type The type of transform to create.
 * @param transform_parameters Any parameters required by the transform,
 *   or NULL if the specified type of transform does not
 *   require any parameters.
 * @param transform Address of an SKB_Transform pointer that will be set
 *   to point to the newly created SKB_Transform object.
 *   This object must be released by calling SKB_Transform_Release when no
 *   longer needed.
 */
SKB_EXPORT SKB_Result
SKB_Engine_CreateTransform(SKB_Engine*       self,
                           SKB_TransformType transform_type,
                           const void*       transform_parameters,
                           SKB_Transform**   transform);

/**
 * Creates an SKB_Cipher object with the specified characteristics.
 *
 * @param self The SKB_Engine responsible for creating the SKB_Cipher.
 * @param cipher_algorithm The algorithm to be used by this cipher.
 * @param cipher_direction An indication as to whether the cipher
 *   will be used for encryption or decryption.
 * @param cipher_flags Flags indicating any special cipher characteristics.
 * @param cipher_parameters Any parameters required by the cipher.
 *   For ciphers in CTR mode, this must point to a SKB_CtrModeCipherParameters
 *   parameters structure, or NULL for the default counter size (16).
 *   For ciphers in GCM mode, this must point to a SKB_GcmCipherParameters
 *   parameters structure.
 *   For other ciphers, this parameter must be NULL.
 * @param cipher_key The cipher key.
 * @param cipher Address of an SKB_Cipher pointer that will be set to
 *   point to the newly created SKB_Cipher object with the specified
 *   characteristics. This object must be released by calling
 *   SKB_Cipher_Release when no longer needed.
 */
SKB_EXPORT SKB_Result
SKB_Engine_CreateCipher(SKB_Engine*           self,
                        SKB_CipherAlgorithm   cipher_algorithm,
                        SKB_CipherDirection   cipher_direction,
                        unsigned int          cipher_flags,
                        const void*           cipher_parameters,
                        const SKB_SecureData* cipher_key,
                        SKB_Cipher**          cipher);

/**
 * Creates an SKB_KeyAgreement object with the specified characteristics.
 *
 * @param self The SKB_Engine responsible for creating the SKB_KeyAgreement.
 * @param key_agreement_algorithm The algorithm to be used by this agreement.
 * @param key_agreement_parameters Any parameters required by the key agreement.
 *   For key agreement using ECC DH algorithm, this must contain
 *   SKB_ECC_Curve enumeration variable with the type of curve to be used.
 *   For other agreements, this parameter must be NULL.
 * @param key_agreement Address of an SKB_KeyAgreement pointer that will be set to
 *   point to the newly created SKB_KeyAgreement object with the specified
 *   characteristics. This object must be released by calling
 *   SKB_KeyAgreement_Release when no longer needed.
 */
SKB_EXPORT SKB_Result
SKB_Engine_CreateKeyAgreement(SKB_Engine*               self,
                              SKB_KeyAgreementAlgorithm key_agreement_algorithm,
                              const void*               key_agreement_parameters,
                              SKB_KeyAgreement**        key_agreement);

/**
 * Reads data from plain and encrypts using specified encryption algorithm.
 * This is similar to SKB_Engine_CreateDataFromWrapped, but uses encryption instead
 * of decryption.
 * The result is stored in a new SecureData object.
 *
 * @param self The SKB_Engine responsible for creating the SKB_SecureData.
 * @param plain The bytes to be wrapped and then represented by
 *   a new SKB_SecureData.
 * @param plain_size The number of bytes in the 'plain' parameter.
 * @param data_type The data type to be used for the SKB_SecureData created by
 *   this method.
 * @param plain_format The data format to be used for the SKB_SecureData created by
 *   this method.
 * @param algorithm The cryptographic algorithm to use for encrypting
 *   the plain bytes (SKB_CIPHER_ALGORITHM_NULL is not allowed here).
 * @param encryption_parameters Parameters for the algorithm.
 * @param encryption_key Pointer to an SKB_SecureData object representing the key
 *   for encrypting the data.
 * @param iv Pointer to the Initialization Vector, if required by the algorithm, or
 *   NULL if no Initialization Vector is required, or if the Initialization Vector is
 *   implicitly all zeros.
 * @param iv_size Size in bytes of the Initialization Vector. Set to 0 if the iv
 * parameter is NULL.
 * @param data Address of an SKB_SecureData pointer that will be set to point
 *   to a new SKB_SecureData object representing the result of encrypting
 *   the specified bytes. This object must be released by calling
 *   SKB_SecureData_Release when no longer needed.
 */
SKB_EXPORT SKB_Result
SKB_Engine_WrapDataFromPlain(SKB_Engine*           self,
                             const SKB_Byte*       plain,
                             SKB_Size              plain_size,
                             SKB_DataType          data_type,
                             SKB_DataFormat        plain_format,
                             SKB_CipherAlgorithm   algorithm,
                             const void*           encryption_parameters,
                             const SKB_SecureData* encryption_key,
                             const SKB_Byte*       iv,
                             SKB_Size              iv_size,
                             SKB_SecureData**      data);

/**
 * This method performs upgrade of legacy exported secure data objects.
 * The it reads data exported by older version of SKB and writes data
 * importable using current version of SKB.
 * The upgrade accepts only data exported using SKB_EXPORT_TARGET_PERSISTENT.
 * The upgrade availability depents on SKB configuration.
 *
 * @param self The SKB_Engine object.
 * @param input The previously exported bytes.
 * @param input_size The number of bytes in the 'exported' parameter.
 * @param buffer Memory buffer where the exported data is to be written, or
 *   NULL if you just want the method to return, in *buffer_size, a number of
 *   bytes sufficient to hold the exported data. The memory buffer, if
 *   supplied, must be large enough to hold the number of bytes specified
 *   by the buffer_size parameter.
 * @param buffer_size Pointer to the size of the memory buffer, if the
 *   'buffer' parameter is not NULL; otherwise, pointer to a zero value.
 *   This parameter
 *   is in/out: the caller sets the value pointed to to the size of the memory
 *   buffer, and upon return the value pointed to will be equal to the number
 *   of bytes written (or the number of bytes that would be written, if either the
 *   value passed was too small or 'buffer' is NULL).
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 * a buffer was supplied but there is not enough space in it to write the
 * exported data, or a different error code if some other failure occurred.
 */
SKB_EXPORT SKB_Result
SKB_Engine_UpgradeExportedData(SKB_Engine*     self,
                               const SKB_Byte* input,
                               SKB_Size        input_size,
                               SKB_Byte*       buffer,
                               SKB_Size*       buffer_size);

/** @} */

/** @ingroup SKB_SecureData
 * @{
 */

/**
 * Releases the specified SKB_SecureData object.
 * An SKB_SecureData object must be released when it is no longer needed,
 * by calling this method.
 * The object can no longer be used by the caller after this call returns.
 *
 * @param self The SKB_SecureData to release.
 */
SKB_EXPORT SKB_Result
SKB_SecureData_Release(SKB_SecureData* self);

/**
 * Gets information about the data represented by an SKB_SecureData object.
 *
 * @param self The SKB_SecureData whose information is obtained.
 * @param info Address of a pointer to an SKB_DataInfo structure that will be
 * populated with the requested information.
 */
SKB_EXPORT SKB_Result
SKB_SecureData_GetInfo(const SKB_SecureData* self, SKB_DataInfo* info);

/**
 * Exports the secret data bytes represented by a specified SKB_SecureData
 * object. This method serializes and encrypts the data bytes
 * such that the caller will be returned a protected form of the bytes
 * that can later be reloaded into an SKB_Engine, that is,
 * converted back to their original form and represented
 * by an SKB_SecureData object, using the SKB_Engine_CreateDataFromExported
 * method.
 *
 * An example of what this enables is storage by the caller of the protected
 * (exported) form for later use.
 *
 * If the output buffer you pass to this method is not large enough to hold
 * the exported data, this method sets *buffer_size to the number of bytes
 * required, and returns SKB_ERROR_BUFFER_TOO_SMALL. If you like, you can find
 * out in advance the maximum size the output buffer should be by
 * first calling this method with NULL for the 'buffer' parameter. In that case,
 * the method outputs, in *buffer_size, the maximum number of bytes required,
 * and returns SKB_SUCCESS.
 *
 * @param self The SKB_SecureData whose exported serialized payload is obtained.
 * @param target The target of the export. If the target is
 *   SKB_EXPORT_TARGET_PERSISTENT, the exported data can be reloaded in an engine
 *   even after a complete reset/reboot of the CPU or system hosting the engine.
 *   If the target is SKB_EXPORT_TARGET_CROSS_ENGINE,
 *   the data can be reloaded in the same or a different SKB_Engine, as long as
 *   a reboot/reset has not occurred, and
 *   the engine from which the data was exported and the engine into which it
 *   is loaded are considered to be compatible. (They can share some common state,
 *   which typically does not persist across a CPU or security processor
 *   shutdown or reset.) If the target is SKB_EXPORT_TARGET_CUSTOM, the export
 *   is customized according to the specified target_parameters.
 * @param target_parameters Parameters for a custom export, or NULL if
 *   target is not SKB_EXPORT_TARGET_CUSTOM.
 * @param buffer Memory buffer where the exported data is to be written, or
 *   NULL if you just want the method to return, in *buffer_size, a number of
 *   bytes sufficient to hold the exported data. The memory buffer, if
 *   supplied, must be large enough to hold the number of bytes specified
 *   by the buffer_size parameter.
 * @param buffer_size Pointer to the size of the memory buffer, if the
 *   'buffer' parameter is not NULL; otherwise, pointer to a zero value.
 *   This parameter
 *   is in/out: the caller sets the value pointed to to the size of the memory
 *   buffer, and upon return the value pointed to will be equal to the number
 *   of bytes written (or the number of bytes that would be written, if either the
 *   value passed was too small or 'buffer' is NULL).
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 * a buffer was supplied but there is not enough space in it to write the
 * exported data, or a different error code if some other failure occurred.
 */
SKB_EXPORT SKB_Result
SKB_SecureData_Export(const SKB_SecureData* self,
                      SKB_ExportTarget      target,
                      const void*           target_parameters,
                      SKB_Byte*             buffer,
                      SKB_Size*             buffer_size);

/**
 * Wraps the secret data bytes represented by a specified SKB_SecureData
 * object. This method encrypts the data bytes stored in SKB_SecureData object and
 * returns the encrypted buffer of bytes.
 *
 * Wrapped data is data that has been encrypted. Frequently, it is a key that has been
 * encrypted using another key.
 * You pass this method the secure data object, and information about the encryption
 * algorithm.
 *
 * If the output buffer you pass to this method is not large enough to hold
 * the exported data, this method sets *buffer_size to the number of bytes
 * required, and returns SKB_ERROR_BUFFER_TOO_SMALL. If you like, you can find
 * out in advance the maximum size the output buffer should be by
 * first calling this method with NULL for the 'buffer' parameter. In that case,
 * the method outputs, in *buffer_size, the maximum number of bytes required,
 * and returns SKB_SUCCESS.
 *
 * @param self The SKB_SecureData whose encrypted payload is obtained.
 * @param wrapping_algorithm The cryptographic algorithm that to use to encrypt
 *   the wrapped bytes (SKB_CIPHER_ALGORITHM_NULL is not supported).
 * @param wrapping_parameters Parameters for the algorithm.
 * @param wrapping_key Pointer to an SKB_SecureData object representing the key
 *   needed to encrypt the data (passing NULL is not supported).
 * @param buffer Memory buffer where the wrapped data is to be written, or
 *   NULL if you just want the method to return, in *buffer_size, a number of
 *   bytes sufficient to hold the wrapped data. The memory buffer, if
 *   supplied, must be large enough to hold the number of bytes specified
 *   by the buffer_size parameter.
 * @param buffer_size Pointer to the size of the memory buffer, if the
 *   'buffer' parameter is not NULL; otherwise, pointer to a zero value.
 *   This parameter
 *   is in/out: the caller sets the value pointed to to the size of the memory
 *   buffer, and upon return the value pointed to will be equal to the number
 *   of bytes written (or the number of bytes that would be written, if either the
 *   value passed was too small or 'buffer' is NULL).
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 * a buffer was supplied but there is not enough space in it to write the
 * exported data, or a different error code if some other failure occurred.
 */

SKB_EXPORT SKB_Result
SKB_SecureData_Wrap(const SKB_SecureData* self,
                    SKB_CipherAlgorithm   wrapping_algorithm,
                    const void*           wrapping_parameters,
                    const SKB_SecureData* wrapping_key,
                    SKB_Byte*             buffer,
                    SKB_Size*             buffer_size);

/**
 * Derives a new SKB_SecureData object from an existing one.
 *
 * @param self The SKB_SecureData whose derivative is obtained.
 * @param algorithm The derivation algorithm.
 * @param parameters Parameters for the derivation algorithm, or NULL if
 *   the algorithm does not require any parameters.
 * @param data Address of an SKB_SecureData pointer that will be set to point
 *   to a new SKB_SecureData object representing the derived data.
 *   This object must be released by calling SKB_SecureData_Release when no
 *   longer needed.
 */
SKB_EXPORT SKB_Result
SKB_SecureData_Derive(const SKB_SecureData*   self,
                      SKB_DerivationAlgorithm algorithm,
                      const void*             parameters,
                      SKB_SecureData**        data);

/**
 * Gets the public key from SKB_SecureData object if it contains a private key.
 * For non-private keys, the function will return SKB_ERROR_NOT_SUPPORTED.
 *
 * @param self The SKB_SecureData whose derivative is obtained.
 * @param format The data format in which to store the public key.
 * @param parameters Parameters for the public key generation algorithm,
 *   or NULL if the algorithm does not require any parameters.
 * @param output Buffer where the the public key is to be written, or
 *   NULL if you just want the method to return, in *output_size, a
 *   number of bytes sufficient to hold the output. The buffer, if supplied,
 *   must be large enough to hold the number of bytes specified by the
 *   output_size parameter.
 * @param output_size Pointer to the size of the output buffer for the public key,
 *   if the 'output' parameter is not NULL; otherwise, pointer to a zero value.
 *   This  parameter is in/out: the caller sets the value pointed to to the
 *   size of the  buffer, and upon return the value pointed to will be equal
 *   to the number of bytes written (or the number of bytes that would be
 *   written, if either the value passed were too small or 'output' were NULL).
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 * a buffer was supplied but there is not enough space in it to write the
 * output, or a different error code if some other failure occurred.
 */
SKB_Result
SKB_EXPORT SKB_SecureData_GetPublicKey(const SKB_SecureData* self,
                            SKB_DataFormat        format,
                            const void*           parameters,
                            SKB_Byte*             output,
                            SKB_Size*             output_size);

/** @} */

/** @ingroup SKB_Transform
 * @{
 */

/**
 * Releases the specified SKB_Transform object.
 * An SKB_Transform object must be released when it is no longer needed,
 * by calling this method.
 * The object can no longer be used by the caller after this call returns.
 *
 * @param self The SKB_Transform to release.
 */
SKB_EXPORT SKB_Result
SKB_Transform_Release(SKB_Transform* self);

/**
 * Adds caller-supplied bytes to the specified transform.
 *
 * @param self The SKB_Transform to which bytes should be added.
 * @param data The bytes to be added.
 * @param data_size The number of bytes in the 'data' parameter.
 */
SKB_EXPORT SKB_Result
SKB_Transform_AddBytes(SKB_Transform*  self,
                       const SKB_Byte* data,
                       SKB_Size        data_size);

/**
 * Adds the data bytes represented by an SKB_SecureData object to
 * the transform.
 * Only SKB_SecureData objects of the following types can be used:
 *  SKB_DATA_TYPE_BYTES
 *
 * @param self The SKB_Transform to which the bytes should be added.
 * @param data The SKB_SecureData representing the secret data whose
 * bytes should be added to the transform.
 */
SKB_EXPORT SKB_Result
SKB_Transform_AddSecureData(SKB_Transform* self, const SKB_SecureData* data);

/**
 * Gets the output of the transform. That is, after you have
 * supplied to the transform all the input data it needs
 * (by calls to SKB_Transform_AddSecureData and/or
 * SKB_Transform_AddBytes), you call this method to have the
 * transform operation (such as a digest calculation) executed
 * and the result returned. After this method has been called, no other
 * method can be called on the SKB_Transform object but SKB_Transform_Release.
 *
 * If the output buffer you pass to this method is not large enough to hold
 * the transform output, this method sets *output_size to the number of bytes
 * required, and returns SKB_ERROR_BUFFER_TOO_SMALL. If you like, you can find
 * out in advance the maximum size the output buffer should be by
 * first calling this method with NULL for the 'output' parameter. In that case,
 * the method outputs, in *output_size, the maximum number of bytes required,
 * and returns SKB_SUCCESS.
 *
 * @param self The SKB_Transform whose output will be returned.
 * @param output Buffer where the output of the transform operation is to be
 *   written, or NULL if you just want the method to return, in *output_size,
 *   a number of bytes sufficient to hold the output. The buffer, if
 *   supplied, must be large enough to hold the number of bytes specified
 *   by the output_size parameter.
 * @param output_size Pointer to the size of the output buffer, if the
 *   'output' parameter is not NULL; otherwise, pointer to a zero value. This
 *   parameter is in/out: the caller sets the value pointed to to the size of the
 *   buffer, and upon return the value pointed to will be equal to the number
 *   of bytes written (or the number of bytes that would be written, if either the
 *   value passed was too small or 'output' is NULL).
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 * a buffer was supplied but there is not enough space in it to write the
 * output, or a different error code if some other failure occurred.
 */
SKB_EXPORT SKB_Result
SKB_Transform_GetOutput(SKB_Transform* self,
                        SKB_Byte*      output,
                        SKB_Size*      output_size);

/** @} */

/** @ingroup SKB_Cipher
 * @{
 */

/**
 * Executes a cipher algorithm on the specified input buffer
 * bytes, and places the result in the specified output buffer.
 *
 * If the output buffer you pass to this method is not large enough to hold
 * the cipher output, this method sets *out_buffer_size to the number of bytes
 * required, and returns SKB_ERROR_BUFFER_TOO_SMALL. If you like, you can find
 * out in advance the maximum size the output buffer should be by
 * first calling this method with NULL for the 'out_buffer' parameter. In that case,
 * the method outputs, in *out_buffer_size, the maximum number of bytes required,
 * and returns SKB_SUCCESS.
 *
 * @param self The SKB_Cipher whose algorithm will be executed.
 * @param in_buffer The buffer of bytes on which to execute
 *   the cipher algorithm. For block ciphers, this MUST point to the beginning
 *   of a cipher block.
 * @param in_buffer_size The number of bytes in in_buffer. For ciphers in ECB or CBC mode,
 *   this MUST be a multiple of the cipher block size. For RSA ciphers, this must be
 *   the size of the entire encrypted message.
 * @param out_buffer The buffer to which the output is to be written, or
 *   NULL if you just want the method to return, in *out_buffer_size, a number of
 *   bytes sufficient to hold the output. The memory buffer, if
 *   supplied, must be large enough to hold the number of bytes specified
 *   by the out_buffer_size parameter.
 * @param out_buffer_size Pointer to the size of out_buffer, if the
 *   out_buffer parameter is not NULL; otherwise, pointer to a zero value.
 *   This parameter
 *   is in/out: the caller sets the value pointed to to the size of the
 *   buffer, and upon return the value pointed to will be equal to the number
 *   of bytes written (or the number of bytes that would be written, if either the
 *   value passed was too small or out_buffer is NULL).
 * @param iv Pointer to the Initialization Vector, if required by the algorithm, or
 *   NULL if no Initialization Vector is required, or if the Initialization Vector is
 *   implicitly all zeros.
 * @param iv_size Size in bytes of the Initialization Vector. Set to 0 if the iv
 *   parameter is NULL.
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 *   a buffer was supplied but there is not enough space in it to write the
 *   output, or a different error code if some other failure occurred.
 */
SKB_EXPORT SKB_Result
SKB_Cipher_ProcessBuffer(SKB_Cipher*     self,
                         const SKB_Byte* in_buffer,
                         SKB_Size        in_buffer_size,
                         SKB_Byte*       out_buffer,
                         SKB_Size*       out_buffer_size,
                         const SKB_Byte* iv,
                         SKB_Size        iv_size);

/**
 * The last call for cipher operations that require additional processing after all
 * plaintext/ciphertext has been processed. Supported by only select cipher
 * algorithms such as SKB_CIPHER_ALGORITHM_AES_XXX_GCM. After this call,
 * calls to SKB_Cipher_ProcessAad and SKB_Cipher_ProcessBuffer as well as
 * repeated call to SKB_Cipher_ProcessFinal on the same cipher object will
 * return SKB_ERROR_INVALID_STATE.
 *
 * @param self The SKB_Cipher whose algorithm will be executed.
 * @param parameters Any parameters required by the cipher.
 *   For ciphers in GCM mode, this must point to the SKB_AuthenticationParameters
 *   structure and will have authentication_tag written in it in
 *   case of encryption.
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 *   a buffer was supplied but there is not enough space in it to write the
 *   output, or a different error code if some other failure occurred.
 *   For ciphers in GCM mode during decryption the authentication tag in
 *   SKB_AuthenticationParameters structure will be compared to calculated tag and
 *   error code SKB_ERROR_AUTHENTICATION_FAILURE will be returned in case of
 *   mismatch.
 */
SKB_Result
SKB_Cipher_ProcessFinal(SKB_Cipher* self,
                        const void* parameters);

/**
 * Adds additional authenticated data to SKB_Cipher object.
 * Currently supported by only select cipher algorithms such
 * as SKB_CIPHER_ALGORITHM_AES_XXX_GCM. This function can be called
 * only before SKB_Cipher_ProcessBuffer and SKB_Cipher_ProcessFinal
 * calls are made.
 *
 * @param self The SKB_Cipher whose algorithm will be executed.
 * @param in_buffer The buffer of bytes which to add as additional authenticated data.
 * @param in_buffer_size The number of bytes in in_buffer.
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_INVALID_STATE if
 *   called after SKB_Cipher_ProcessBuffer or SKB_Cipher_ProcessFinal
 *   or a different error code if some other failure occurred.
 */

SKB_Result
SKB_Cipher_ProcessAad(SKB_Cipher*     self,
                      const SKB_Byte* in_buffer,
                      SKB_Size        in_buffer_size);

/**
 * Releases the specified SKB_Cipher object.
 * An SKB_Cipher object must be released when it is no longer needed,
 * by calling this method.
 * The object can no longer be used by the caller after this call returns.
 *
 * @param self The SKB_Cipher to be released.
 *
 * @return SKB_SUCCESS if the call succeeds.
 */

SKB_EXPORT SKB_Result
SKB_Cipher_Release(SKB_Cipher* self);

/** @} */

/** @ingroup SKB_ECDH
 * @{
 */

/**
 * Returns KeyAgreement key that needs to be exchanged with other party.
 *
 * @param self KeyAgreement object.
 * @param public_key_buffer Memory buffer where the public key is to be
 * written, or NULL if you just want the method to return, in
 * *public_key_buffer_size, a number of bytes sufficient to hold the
 * public key data. The memory buffer, if supplied, must be large enough
 * to hold the number of bytes specified by the buffer_size parameter.
 * @param public_key_buffer_size Pointer to the size of the memory buffer,
 * if the 'public_key_buffer' parameter is not NULL; otherwise, pointer
 * to a zero value.
 * This parameter is in/out: the caller sets the value pointed to to the
 * size of the memory buffer, and upon return the value pointed to will be
 * equal to the number of bytes written (or the number of bytes that would
 * be written, if either the passed was too small or 'exported' is NULL).
 *
 * @return SKB_SUCCESS if the call succeeds, SKB_ERROR_BUFFER_TOO_SMALL if
 * a buffer was supplied but there is not enough space in it to write the
 * exported data, or a different error code if some other failure occurred.
 */
SKB_Result
SKB_EXPORT SKB_KeyAgreement_GetPublicKey(SKB_KeyAgreement* self,
                              SKB_Byte*         public_key_buffer,
                              SKB_Size*         public_key_buffer_size);

/**
 * Uses SKB_KeyAgreement public key from other party to create secret shared key.
 *
 * @param self SKB_KeyAgreement object.
 * @param peer_public_key Memory buffer with the public key from other
 * party.
 * @param peer_public_key_size Size of the memory buffer peer_public_key.
 * @param secret_size Expected size of resulting secret shared key.
 * @param secret Address of SKB_SecureData pointer that will be set to point
 * a new SKB_SecureData object. This object must be released by calling
 * SKB_SecureData_Release when no longer needed. This secure data object
 * can be used as a common AES key for both parties.
 */

SKB_Result
SKB_EXPORT SKB_KeyAgreement_ComputeSecret(SKB_KeyAgreement* self,
                               const SKB_Byte*   peer_public_key,
                               SKB_Size          peer_public_key_size,
                               SKB_Size          secret_size,
                               SKB_SecureData**  secret);

/**
 * Releases the specified SKB_KeyAgreement object.
 * An SKB_KeyAgreement object must be released when it is no longer needed,
 * by calling this method.
 * The object can no longer be used by the caller after this call returns.
 *
 * @param self The SKB_KeyAgreement to release.
 */
SKB_Result
SKB_EXPORT SKB_KeyAgreement_Release(SKB_KeyAgreement* self);

/** @} */

#if defined(__cplusplus)
}
#endif

#endif /* _SKB_SECURE_KEY_BOX_H_ */
