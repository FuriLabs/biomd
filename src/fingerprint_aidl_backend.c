/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 * Copyright (C) 2026 Herman van Hazendonk <github.com@herrie.org>
 */

#include "fingerprint_aidl_backend.h"
#include "fingerprint_binder_aidl.h"
#include <glib.h>

typedef struct {
    BiomFingerprintAidl *aidl;
    GDBusConnection *connection;
} FingerprintAidlData;

static void
aidl_enroll_result_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.enroll_result)
        backend->callbacks.enroll_result(backend->callbacks.user_data, finger_id, group_id, remaining);
}

static void
aidl_acquired_cb(gpointer user_data, FingerprintAcquiredInfo acquired_info, guint32 vendor_code)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.acquired)
        backend->callbacks.acquired(backend->callbacks.user_data, (guint32)acquired_info, vendor_code);
}

static void
aidl_authenticated_cb(gpointer user_data, guint32 finger_id, guint32 group_id)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.authenticated)
        backend->callbacks.authenticated(backend->callbacks.user_data, finger_id, group_id);
}

static void
aidl_error_cb(gpointer user_data, FingerprintError error_code, guint32 vendor_code)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.error)
        backend->callbacks.error(backend->callbacks.user_data, (guint32)error_code, vendor_code);
}

static void
aidl_removed_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.removed)
        backend->callbacks.removed(backend->callbacks.user_data, finger_id, group_id, remaining);
}

static void
aidl_enumerate_cb(gpointer user_data, guint32 finger_id, guint32 group_id, guint32 remaining)
{
    FingerprintBackend *backend = (FingerprintBackend *)user_data;
    if (backend && backend->callbacks.enumerate)
        backend->callbacks.enumerate(backend->callbacks.user_data, finger_id, group_id, remaining);
}

static gboolean
aidl_is_available(FingerprintBackend *self)
{
    FingerprintAidlData *data = (FingerprintAidlData *)self->impl_data;
    return data && data->aidl && fingerprint_aidl_is_available(data->aidl);
}

static gboolean
aidl_setup_default(FingerprintBackend *self)
{
    FingerprintAidlData *data = (FingerprintAidlData *)self->impl_data;
    return data && data->aidl && fingerprint_aidl_setup(data->aidl);
}

static gboolean
aidl_perform_enrollment(FingerprintBackend *self, const gchar *password, guint32 timeout)
{
    FingerprintAidlData *data = (FingerprintAidlData *)self->impl_data;
    return data && data->aidl && fingerprint_aidl_perform_enrollment(data->aidl, password, timeout);
}

static gboolean
aidl_perform_authentication(FingerprintBackend *self)
{
    FingerprintAidlData *data = (FingerprintAidlData *)self->impl_data;
    return data && data->aidl && fingerprint_aidl_perform_authentication(data->aidl);
}

static gboolean
aidl_cancel_operation(FingerprintBackend *self)
{
    FingerprintAidlData *data = (FingerprintAidlData *)self->impl_data;
    return data && data->aidl && fingerprint_aidl_cancel_operation(data->aidl);
}

static gboolean
aidl_remove_fingerprint(FingerprintBackend *self, guint32 finger_id)
{
    FingerprintAidlData *data = (FingerprintAidlData *)self->impl_data;
    return data && data->aidl && fingerprint_aidl_remove_fingerprint(data->aidl, finger_id);
}

static void
aidl_cleanup(FingerprintBackend *self)
{
    FingerprintAidlData *data = (FingerprintAidlData *)self->impl_data;
    if (data) {
        if (data->aidl)
            fingerprint_aidl_cleanup(data->aidl);
        g_free(data);
        self->impl_data = NULL;
    }
}

FingerprintBackend*
fingerprint_aidl_backend_new(FingerprintBackendCallbacks callbacks)
{
    FingerprintBackendVTable vtable = {
        .is_available = aidl_is_available,
        .setup_default = aidl_setup_default,
        .perform_enrollment = aidl_perform_enrollment,
        .perform_authentication = aidl_perform_authentication,
        .cancel_operation = aidl_cancel_operation,
        .remove_fingerprint = aidl_remove_fingerprint,
        .cleanup = aidl_cleanup
    };

    FingerprintBackend *backend = fingerprint_backend_new(vtable, callbacks);
    if (!backend)
        return NULL;

    FingerprintAidlData *data = g_new0(FingerprintAidlData, 1);
    backend->impl_data = data;

    FingerprintAidlCallbacks aidl_callbacks = {
        .enroll_result = aidl_enroll_result_cb,
        .acquired = aidl_acquired_cb,
        .authenticated = aidl_authenticated_cb,
        .error = aidl_error_cb,
        .removed = aidl_removed_cb,
        .enumerate = aidl_enumerate_cb
    };

    data->aidl = fingerprint_aidl_init(&aidl_callbacks, backend);
    if (!data->aidl) {
        g_debug("AIDL fingerprint HAL not usable");
        fingerprint_backend_free(backend);
        return NULL;
    }

    return backend;
}
