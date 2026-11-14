/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 * Copyright (C) 2026 Herman van Hazendonk <github.com@herrie.org>
 */

#ifndef FINGERPRINT_AIDL_BACKEND_H
#define FINGERPRINT_AIDL_BACKEND_H

#include <glib.h>
#include "fingerprint_backend.h"

/**
* Create a new AIDL backend instance with the specified callbacks
*
* @param callbacks Callback functions to be invoked by the backend
* @return A new FingerprintBackend instance or NULL if creation failed
*/
FingerprintBackend *
fingerprint_aidl_backend_new(FingerprintBackendCallbacks callbacks);

#endif // FINGERPRINT_AIDL_BACKEND_H
