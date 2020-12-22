/*****************************************************************
|
|   whiteCryption Secure Key Box
|
|   $Id: SkbPlatform.h 13245 2019-05-09 12:36:36Z nlarka $
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

#pragma once

/*----------------------------------------------------------------------
|   includes
+---------------------------------------------------------------------*/

#include <stdarg.h>
#include "SkbSecureKeyBox.h"

/*----------------------------------------------------------------------
|   functions
+---------------------------------------------------------------------*/

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Generates random bytes.
 *
 * @param buffer Pointer to the output buffer.
 *
 * @param count Number of random bytes to be written in the buffer.
 *
 * @returns SKB_SUCCESS if no errors occurred.
 */
SKB_Result
SKB_GetRandomBytes(SKB_Byte* buffer, SKB_Size count);

typedef struct SKB_Mutex SKB_Mutex;

/**
 * Creates a new mutex.
 *
 * @param mutex Pointer will be set to the newly created mutex.
 *
 * @returns SKB_SUCCESS if no errors occurred.
 */
SKB_Result
SKB_Mutex_Create(SKB_Mutex** mutex);

/**
 * Locks a mutex.
 *
 * @param mutex Pointer to the mutex that is to be locked.
 *
 * @returns SKB_SUCCESS if no errors ocurred.
 */
SKB_Result
SKB_Mutex_Lock(SKB_Mutex* mutex);

/**
 * Unlocks a mutex.
 *
 * @param mutex Pointer to the mutex that is to be unlocked.
 *
 * @returns SKB_SUCCESS if no errors ocurred.
 */
SKB_Result
SKB_Mutex_Unlock(SKB_Mutex* mutex);

/**
 * Destroys a mutex.
 *
 * @param mutex Pointer to the mutex that is to be destroyed.
 *
 * @returns SKB_SUCCESS if no errors ocurred.
 */
SKB_Result
SKB_Mutex_Destroy(SKB_Mutex* mutex);

/**
 * Stops execution to run a debugger.
 * Used only in debug builds.
 */
void SKB_StopInDebugger();

/**
 * Formats and logs an error message. Calls SKB_OutputLogMessage for actual output.
 * Used only in evaluation builds.
 *
 * @param file_path file path.
 * @param line line at which error occured.
 * @param result SKB result.
 */
void SKB_LogMessage(const char* file_path, const int line, SKB_Result result);

/**
 * Platform specific function to output message to a log file or stdout.
 * Used only in evaluation builds.
 *
 * @param message message.
 */
void SKB_OutputLogMessage(const char* message);


/**
 * The following functions are used within the Secure Key Box library to register and retrieve
 * currently enabled features (algorithms), which are specified in the SkbModules.h file.
 */
SKB_EXPORT void SKB_RegisterModules();
SKB_EXPORT SKB_Size SKB_GetModuleCount();
typedef struct SKB_Module SKB_Module;
SKB_EXPORT SKB_Module** SKB_GetModules();

/**
 * Sets path where config files are located. Must be called before SKB_Engine_GetInstance().
 * If this function is not called, then platform-specific path is used.
 *
 * @param dir_path path.
 */
SKB_Result SKB_SetTempDir(const char* dir_path);

/**
 * Returns static buffer containing path to store key cache file.
 * It's expected to have permissions to create a new file if it does not exist.
 *
 * @returns buffer containing database path.
 */
const char* SKB_GetKeyCacheDBPath();

/**
 * Returns static buffer containing path to store Secure Key Box configuration file.
 * The configuration file will contain all the features of evaluation version
 * of Secure Key Box library which are called by the application using it.
 * It's expected to have permissions to create a new file if it does not exist.
 *
 * @returns buffer containing config path.
 */
const char* SKB_GetConfigPath();

/**
* Returns static buffer containing path to store Secure Key Box key flow log file.
* It's expected to have permissions to create a new file if it does not exist.
*
* @returns buffer containing config path.
*/
const char* SKB_GetKeyFlowLogFile();

typedef enum {
    SKB_USE_COMPACT_KEYCACHE     = 1 << 0, // Use SHA512 for key cache entry IDs
    SKB_USE_EXPORT_KEYCACHE      = 1 << 1, // Cache exported/imported keys (will be used when re-importing)
    SKB_USE_RSA_KEYCACHE         = 1 << 2, // Cache initialized RSA keys (will be used when re-initializing)
    SKB_USE_PERSISTENT_KEYCACHE  = 1 << 3, // Cache will be stored in a file
    SKB_SAVE_KEYCACHE_FREQUENTLY = 1 << 4, // Cache will be stored on each SKB_KeyCache_SetData() call
    SKB_EVAL_ENABLE_LOGGING      = 1 << 5, // Flag to turn on logging functionality (only for evaluation builds)
    SKB_ENABLE_KEY_FLOW_LOGGING  = 1 << 6  // Flag to turn on logging of SKB key flow
} SKB_PlatformFlags;

/**
 * Sets various flags, see SKB_PlatformFlags enum. Must be called before SKB_Engine_GetInstance().
 *
 * @param flags flags to set.
 */
void SKB_SetFlags(unsigned int flags);

/**
 * Retrieves current SKB flags. These could be changed after SKB_Engine instance is created, therefore
 * SKB_Engine_GetInfo() should be used to get the flags that are used by SKB_Engine instance.
 *
 * @returns currently set flags.
 */
unsigned int SKB_GetFlags();

#if defined(__cplusplus)
}
#endif
