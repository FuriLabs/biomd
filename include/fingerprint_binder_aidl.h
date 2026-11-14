/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 * Copyright (C) 2026 Herman van Hazendonk <github.com@herrie.org>
 */

#ifndef FINGERPRINT_BINDER_AIDL_H
#define FINGERPRINT_BINDER_AIDL_H

#include <glib.h>
#include <gio/gio.h>
#include "fingerprint_hidl_backend.h"

typedef struct _BiomFingerprintAidl BiomFingerprintAidl;

typedef struct {
    /**
     * Called when enrollment progress is made
     * @param user_data User-provided data pointer
     * @param finger_id ID of the finger being enrolled
     * @param group_id Group ID for the fingerprint (always 0 on AIDL)
     * @param remaining Number of steps remaining for enrollment
     */
    void (*enroll_result)(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining);

    /**
     * Called when fingerprint sample is acquired
     * @param user_data User-provided data pointer
     * @param acquired_info Information about the quality of the acquired sample
     * @param vendor_code Vendor-specific information
     */
    void (*acquired)(gpointer user_data, FingerprintAcquiredInfo acquired_info, guint32 vendor_code);

    /**
     * Called when authentication is successful
     * @param user_data User-provided data pointer
     * @param finger_id ID of the authenticated finger
     * @param group_id Group ID for the fingerprint (always 0 on AIDL)
     */
    void (*authenticated)(gpointer user_data, guint32 finger_id, guint32 group_id);

    /**
     * Called when an error occurs
     * @param user_data User-provided data pointer
     * @param error_code Error code describing what went wrong
     * @param vendor_code Vendor-specific error information
     */
    void (*error)(gpointer user_data, FingerprintError error_code, guint32 vendor_code);

    /**
     * Called when a fingerprint is removed
     * @param user_data User-provided data pointer
     * @param finger_id ID of the removed finger
     * @param group_id Group ID for the fingerprint (always 0 on AIDL)
     * @param remaining Number of fingerprints still to come in this batch
     */
    void (*removed)(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining);

    /**
     * Called when enumerating through enrolled fingerprints
     * @param user_data User-provided data pointer
     * @param finger_id ID of the current finger in enumeration
     * @param group_id Group ID for the fingerprint (always 0 on AIDL)
     * @param remaining Number of fingerprints remaining to enumerate
     */
    void (*enumerate)(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining);
} FingerprintAidlCallbacks;

/**
 * Initialize the AIDL fingerprint backend
 *
 * @param callbacks Callback functions to be invoked by the backend
 * @param user_data User data to pass to callbacks
 * @return A new BiomFingerprintAidl instance or NULL on failure
 */
BiomFingerprintAidl*
fingerprint_aidl_init(const FingerprintAidlCallbacks *callbacks, gpointer user_data);

/**
 * Check if the AIDL fingerprint hardware is available
 * @param aidl The AIDL instance
 * @return TRUE if available, FALSE otherwise
 */
gboolean
fingerprint_aidl_is_available(BiomFingerprintAidl *aidl);

/**
 * Set up the default configuration for the AIDL backend
 * @param aidl The AIDL instance
 * @return TRUE on success, FALSE on failure
 */
gboolean
fingerprint_aidl_setup(BiomFingerprintAidl *aidl);

/**
 * Start fingerprint enrollment process
 * @param aidl The AIDL instance
 * @param password Password for secure storage
 * @param timeout_sec Timeout in seconds for the operation
 * @return TRUE on successful start, FALSE on failure
 */
gboolean
fingerprint_aidl_perform_enrollment(BiomFingerprintAidl *aidl, const gchar *password, guint32 timeout_sec);

/**
 * Start fingerprint authentication process
 * @param aidl The AIDL instance
 * @return TRUE on successful start, FALSE on failure
 */
gboolean
fingerprint_aidl_perform_authentication(BiomFingerprintAidl *aidl);

/**
 * Cancel current fingerprint operation
 * @param aidl The AIDL instance
 * @return TRUE on successful cancel, FALSE on failure
 */
gboolean
fingerprint_aidl_cancel_operation(BiomFingerprintAidl *aidl);

/**
 * Remove an enrolled fingerprint
 * @param aidl The AIDL instance
 * @param finger_id ID of fingerprint to remove
 * @return TRUE on success, FALSE on failure
 */
gboolean
fingerprint_aidl_remove_fingerprint(BiomFingerprintAidl *aidl, guint32 finger_id);

/**
 * Clean up AIDL resources
 * @param aidl The AIDL instance to clean up
 */
void
fingerprint_aidl_cleanup(BiomFingerprintAidl *aidl);

#endif // FINGERPRINT_BINDER_AIDL_H
