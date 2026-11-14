/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Herman van Hazendonk <github.com@herrie.org>
 */

#ifndef FACE_DISABLED_BACKEND_H
#define FACE_DISABLED_BACKEND_H

#include <glib.h>
#include "face_backend.h"

/**
 * Create a new disabled backend instance.
 *
 * Used when biomd is built with WITH_FACE=0. This backend is of type
 * TYPE_UNKNOWN and provides no face support.
 *
 * @param callbacks Callback functions to be invoked by the backend
 * @return A new FaceBackend instance or NULL if creation failed
 */
FaceBackend *
face_disabled_backend_new(FaceBackendCallbacks callbacks);

#endif // FACE_DISABLED_BACKEND_H
