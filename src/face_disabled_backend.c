/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Herman van Hazendonk <github.com@herrie.org>
 */

#include "face_disabled_backend.h"

#include <glib.h>

static gboolean
disabled_is_available(FaceBackend *self)
{
    (void) self;
    return FALSE;
}

static FaceImplementationType
disabled_get_implementation_type(FaceBackend *self)
{
    (void) self;
    return TYPE_UNKNOWN;
}

static gboolean
disabled_setup_default(FaceBackend *self)
{
    (void) self;
    return FALSE;
}

static gboolean
disabled_start_enrollment(FaceBackend *self)
{
    (void) self;
    return FALSE;
}

static gboolean
disabled_start_recognition(FaceBackend *self)
{
    (void) self;
    return FALSE;
}

static gboolean
disabled_cancel_operation(FaceBackend *self)
{
    (void) self;
    return FALSE;
}

static gboolean
disabled_submit_frame(FaceBackend *self,
                      gint fd,
                      gint width,
                      gint height,
                      gint channels,
                      guint32 format)
{
    (void) self;
    (void) fd;
    (void) width;
    (void) height;
    (void) channels;
    (void) format;
    return FALSE;
}

static gboolean
disabled_is_enrolled(FaceBackend *self)
{
    (void) self;
    return FALSE;
}

static gboolean
disabled_remove_face_data(FaceBackend *self)
{
    (void) self;
    return FALSE;
}

static void
disabled_cleanup(FaceBackend *self)
{
    (void) self;
}

FaceBackend *
face_disabled_backend_new(FaceBackendCallbacks callbacks)
{
    FaceBackendVTable vtable = {
        .is_available = disabled_is_available,
        .get_implementation_type = disabled_get_implementation_type,
        .setup_default = disabled_setup_default,
        .start_enrollment = disabled_start_enrollment,
        .start_recognition = disabled_start_recognition,
        .cancel_operation = disabled_cancel_operation,
        .submit_frame = disabled_submit_frame,
        .is_enrolled = disabled_is_enrolled,
        .remove_face_data = disabled_remove_face_data,
        .cleanup = disabled_cleanup
    };

    return face_backend_new(vtable, callbacks);
}
