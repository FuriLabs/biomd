/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Bardia Moshiri <bardia@furilabs.com>
 * Copyright (C) 2026 Herman van Hazendonk <github.com@herrie.org>
 */

#include "fingerprint_binder_aidl.h"
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <gbinder.h>

/*
 * Transaction codes follow the method order in the .aidl files, so the enums
 * below must stay in that order.
 */

#define BINDER_DEVICE       "/dev/binder"

#define FP_AIDL             "android.hardware.biometrics.fingerprint.IFingerprint"
#define FP_AIDL_SESSION     "android.hardware.biometrics.fingerprint.ISession"
#define FP_AIDL_CALLBACK    "android.hardware.biometrics.fingerprint.ISessionCallback"
#define FP_AIDL_CANCEL      "android.hardware.biometrics.common.ICancellationSignal"
#define FP_AIDL_SERVICE     FP_AIDL "/default"

#define GK_AIDL             "android.hardware.gatekeeper.IGatekeeper"
#define GK_AIDL_SERVICE     GK_AIDL "/default"

/* android.hardware.biometrics.fingerprint.IFingerprint */
enum FingerprintAidlFunctions {
    FP_GET_SENSOR_PROPS = GBINDER_FIRST_CALL_TRANSACTION,   /* 1 */
    FP_CREATE_SESSION,                                      /* 2 */
};

/* android.hardware.biometrics.fingerprint.ISession */
enum SessionAidlFunctions {
    SESSION_GENERATE_CHALLENGE = GBINDER_FIRST_CALL_TRANSACTION, /* 1 */
    SESSION_REVOKE_CHALLENGE,                               /* 2 */
    SESSION_ENROLL,                                         /* 3 */
    SESSION_AUTHENTICATE,                                   /* 4 */
    SESSION_DETECT_INTERACTION,                             /* 5 */
    SESSION_ENUMERATE_ENROLLMENTS,                          /* 6 */
    SESSION_REMOVE_ENROLLMENTS,                             /* 7 */
    SESSION_GET_AUTHENTICATOR_ID,                           /* 8 */
    SESSION_INVALIDATE_AUTHENTICATOR_ID,                    /* 9 */
    SESSION_RESET_LOCKOUT,                                  /* 10 */
    SESSION_CLOSE,                                          /* 11 */
};

/* android.hardware.biometrics.common.ICancellationSignal */
enum CancellationAidlFunctions {
    CANCELLATION_CANCEL = GBINDER_FIRST_CALL_TRANSACTION,   /* 1 */
};

/* android.hardware.biometrics.fingerprint.ISessionCallback */
enum SessionCallbackAidlFunctions {
    CB_ON_CHALLENGE_GENERATED = GBINDER_FIRST_CALL_TRANSACTION, /* 1 */
    CB_ON_CHALLENGE_REVOKED,                                /* 2 */
    CB_ON_ACQUIRED,                                         /* 3 */
    CB_ON_ERROR,                                            /* 4 */
    CB_ON_ENROLLMENT_PROGRESS,                              /* 5 */
    CB_ON_AUTHENTICATION_SUCCEEDED,                         /* 6 */
    CB_ON_AUTHENTICATION_FAILED,                            /* 7 */
    CB_ON_LOCKOUT_TIMED,                                    /* 8 */
    CB_ON_LOCKOUT_PERMANENT,                                /* 9 */
    CB_ON_LOCKOUT_CLEARED,                                  /* 10 */
    CB_ON_INTERACTION_DETECTED,                             /* 11 */
    CB_ON_ENROLLMENTS_ENUMERATED,                           /* 12 */
    CB_ON_ENROLLMENTS_REMOVED,                              /* 13 */
    CB_ON_AUTHENTICATOR_ID_RETRIEVED,                       /* 14 */
    CB_ON_AUTHENTICATOR_ID_INVALIDATED,                     /* 15 */
    CB_ON_SESSION_CLOSED,                                   /* 16 */
};

/* android.hardware.gatekeeper.IGatekeeper */
enum GatekeeperAidlFunctions {
    GK_AIDL_DELETE_ALL_USERS = GBINDER_FIRST_CALL_TRANSACTION, /* 1 */
    GK_AIDL_DELETE_USER,                                    /* 2 */
    GK_AIDL_ENROLL,                                         /* 3 */
    GK_AIDL_VERIFY,                                         /* 4 */
};

/* android.hardware.biometrics.fingerprint.Error, byte backed but sent as int32 */
typedef enum {
    AIDL_ERROR_UNKNOWN = 0,
    AIDL_ERROR_HW_UNAVAILABLE = 1,
    AIDL_ERROR_UNABLE_TO_PROCESS = 2,
    AIDL_ERROR_TIMEOUT = 3,
    AIDL_ERROR_NO_SPACE = 4,
    AIDL_ERROR_CANCELED = 5,
    AIDL_ERROR_UNABLE_TO_REMOVE = 6,
    AIDL_ERROR_VENDOR = 7,
    AIDL_ERROR_BAD_CALIBRATION = 8,
    AIDL_ERROR_POWER_PRESS = 9,
} AidlError;

/* android.hardware.biometrics.fingerprint.AcquiredInfo, same byte backing */
typedef enum {
    AIDL_ACQUIRED_UNKNOWN = 0,
    AIDL_ACQUIRED_GOOD = 1,
    AIDL_ACQUIRED_PARTIAL = 2,
    AIDL_ACQUIRED_INSUFFICIENT = 3,
    AIDL_ACQUIRED_SENSOR_DIRTY = 4,
    AIDL_ACQUIRED_TOO_SLOW = 5,
    AIDL_ACQUIRED_TOO_FAST = 6,
    AIDL_ACQUIRED_VENDOR = 7,
    AIDL_ACQUIRED_START = 8,
    AIDL_ACQUIRED_TOO_DARK = 9,
    AIDL_ACQUIRED_TOO_BRIGHT = 10,
    AIDL_ACQUIRED_IMMOBILE = 11,
    AIDL_ACQUIRED_RETRYING_CAPTURE = 12,
    AIDL_ACQUIRED_LIFT_TOO_SOON = 13,
    AIDL_ACQUIRED_POWER_PRESS = 14,
} AidlAcquiredInfo;

/* android.hardware.gatekeeper.IGatekeeper status codes */
#define GK_AIDL_STATUS_OK           0
#define GK_AIDL_STATUS_REENROLL     1

/* android.hardware.security.keymint.HardwareAuthToken */
#define HW_AUTH_TOKEN_MAX_MAC 64

typedef struct {
    gint64 challenge;
    gint64 user_id;
    gint64 authenticator_id;
    gint32 authenticator_type;
    gint64 timestamp_ms;
    guint8 mac[HW_AUTH_TOKEN_MAX_MAC];
    gsize mac_len;
    gboolean valid;
} AidlHardwareAuthToken;

struct _BiomFingerprintAidl {
    GBinderServiceManager* sm;

    GBinderRemoteObject* fingerprint_remote;
    GBinderClient* fingerprint_client;

    GBinderRemoteObject* session_remote;
    GBinderClient* session_client;
    GBinderLocalObject* session_callback;

    /* returned by enroll/authenticate, AIDL has no global cancel */
    GBinderRemoteObject* cancel_remote;
    GBinderClient* cancel_client;

    GBinderRemoteObject* gatekeeper_remote;
    GBinderClient* gatekeeper_client;

    gint32 sensor_id;
    gboolean available;

    FingerprintAidlCallbacks callbacks;
    gpointer user_data;
};

static FingerprintError
fingerprint_aidl_map_error(gint32 aidl_error)
{
    switch (aidl_error) {
        case AIDL_ERROR_UNKNOWN:            return FINGERPRINT_ERROR_HW_UNAVAILABLE;
        case AIDL_ERROR_HW_UNAVAILABLE:     return FINGERPRINT_ERROR_HW_UNAVAILABLE;
        case AIDL_ERROR_UNABLE_TO_PROCESS:  return FINGERPRINT_ERROR_UNABLE_TO_PROCESS;
        case AIDL_ERROR_TIMEOUT:            return FINGERPRINT_ERROR_TIMEOUT;
        case AIDL_ERROR_NO_SPACE:           return FINGERPRINT_ERROR_NO_SPACE;
        case AIDL_ERROR_CANCELED:           return FINGERPRINT_ERROR_CANCELED;
        case AIDL_ERROR_UNABLE_TO_REMOVE:   return FINGERPRINT_ERROR_UNABLE_TO_REMOVE;
        case AIDL_ERROR_VENDOR:             return FINGERPRINT_ERROR_VENDOR;
        /* no HIDL equivalent */
        case AIDL_ERROR_BAD_CALIBRATION:    return FINGERPRINT_ERROR_UNABLE_TO_PROCESS;
        case AIDL_ERROR_POWER_PRESS:        return FINGERPRINT_ERROR_UNABLE_TO_PROCESS;
        default:                            return FINGERPRINT_ERROR_VENDOR;
    }
}

static FingerprintAcquiredInfo
fingerprint_aidl_map_acquired(gint32 aidl_info)
{
    switch (aidl_info) {
        case AIDL_ACQUIRED_GOOD:            return FINGERPRINT_ACQUIRED_GOOD;
        case AIDL_ACQUIRED_PARTIAL:         return FINGERPRINT_ACQUIRED_PARTIAL;
        case AIDL_ACQUIRED_INSUFFICIENT:    return FINGERPRINT_ACQUIRED_INSUFFICIENT;
        case AIDL_ACQUIRED_SENSOR_DIRTY:    return FINGERPRINT_ACQUIRED_IMAGER_DIRTY;
        case AIDL_ACQUIRED_TOO_SLOW:        return FINGERPRINT_ACQUIRED_TOO_SLOW;
        case AIDL_ACQUIRED_TOO_FAST:        return FINGERPRINT_ACQUIRED_TOO_FAST;
        case AIDL_ACQUIRED_VENDOR:          return FINGERPRINT_ACQUIRED_VENDOR;
        /* no HIDL equivalent */
        case AIDL_ACQUIRED_UNKNOWN:         return FINGERPRINT_ACQUIRED_INSUFFICIENT;
        case AIDL_ACQUIRED_START:           return FINGERPRINT_ACQUIRED_GOOD;
        default:                            return FINGERPRINT_ACQUIRED_INSUFFICIENT;
    }
}

/* AIDL byte[]: int32 count, then the bytes padded to 4 */
static void
fingerprint_aidl_append_byte_array(GBinderWriter* writer, const void* data, gsize len)
{
    static const guint8 padding[4] = { 0, 0, 0, 0 };
    const gsize aligned = (len + 3) & ~(gsize)3;

    gbinder_writer_append_int32(writer, (gint32)len);
    if (len) {
        gbinder_writer_append_bytes(writer, data, len);
        if (aligned > len)
            gbinder_writer_append_bytes(writer, padding, aligned - len);
    }
}

/* AIDL replies start with an int32 exception code, 0 meaning none */
static gboolean
fingerprint_aidl_reply_ok(GBinderRemoteReply* reply, int status, GBinderReader* reader,
                          const char* what)
{
    gint32 exception = -1;

    if (status != GBINDER_STATUS_OK || !reply) {
        g_warning("%s: binder transaction failed (status %d)", what, status);
        return FALSE;
    }

    gbinder_remote_reply_init_reader(reply, reader);

    if (!gbinder_reader_read_int32(reader, &exception)) {
        g_warning("%s: reply carried no status header", what);
        return FALSE;
    }

    if (exception != 0) {
        g_warning("%s: HAL returned exception %d", what, exception);
        return FALSE;
    }

    return TRUE;
}

/* call a method that returns void */
static gboolean
fingerprint_aidl_call_void(GBinderClient* client, guint32 code, GBinderLocalRequest* req,
                           const char* what)
{
    GBinderRemoteReply* reply;
    GBinderReader reader;
    int status = GBINDER_STATUS_FAILED;
    gboolean ok;

    reply = gbinder_client_transact_sync_reply(client, code, req, &status);
    ok = fingerprint_aidl_reply_ok(reply, status, &reader, what);

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(req);

    return ok;
}

/*
 * HardwareAuthToken on the wire:
 *
 *   int32  parcelable size (this field included)
 *   int64  challenge
 *   int64  userId
 *   int64  authenticatorId
 *   int32  authenticatorType
 *   Timestamp { int32 parcelable size; int64 milliSeconds; }
 *   byte[] mac
 */
#define TIMESTAMP_PARCELABLE_SIZE 12

static void
fingerprint_aidl_write_auth_token(GBinderWriter* writer, const AidlHardwareAuthToken* hat)
{
    static const AidlHardwareAuthToken empty = { 0, 0, 0, 0, 0, { 0 }, 0, FALSE };
    gsize mac_len;
    gint32 size;

    if (!hat)
        hat = &empty;

    mac_len = hat->mac_len;

    /* 4 size + 8 challenge + 8 user + 8 authenticator + 4 type + 12 timestamp
     * + 4 mac count + the padded mac itself */
    size = (gint32)(48 + ((mac_len + 3) & ~(gsize)3));

    gbinder_writer_append_int32(writer, size);
    gbinder_writer_append_int64(writer, hat->challenge);
    gbinder_writer_append_int64(writer, hat->user_id);
    gbinder_writer_append_int64(writer, hat->authenticator_id);
    gbinder_writer_append_int32(writer, hat->authenticator_type);

    gbinder_writer_append_int32(writer, TIMESTAMP_PARCELABLE_SIZE);
    gbinder_writer_append_int64(writer, hat->timestamp_ms);

    fingerprint_aidl_append_byte_array(writer, hat->mac, mac_len);
}

static gboolean
fingerprint_aidl_read_auth_token(GBinderReader* reader, AidlHardwareAuthToken* hat)
{
    gint32 parcelable_size = 0, timestamp_size = 0;
    const void* mac;
    gsize mac_len = 0;

    memset(hat, 0, sizeof(*hat));

    if (!gbinder_reader_read_int32(reader, &parcelable_size) ||
        !gbinder_reader_read_int64(reader, &hat->challenge) ||
        !gbinder_reader_read_int64(reader, &hat->user_id) ||
        !gbinder_reader_read_int64(reader, &hat->authenticator_id) ||
        !gbinder_reader_read_int32(reader, &hat->authenticator_type) ||
        !gbinder_reader_read_int32(reader, &timestamp_size) ||
        !gbinder_reader_read_int64(reader, &hat->timestamp_ms))
        return FALSE;

    mac = gbinder_reader_read_byte_array(reader, &mac_len);
    if (!mac)
        return FALSE;

    if (mac_len > HW_AUTH_TOKEN_MAX_MAC) {
        g_warning("HardwareAuthToken carries a %zu byte mac, which is longer than "
                  "anything this understands", mac_len);
        return FALSE;
    }

    if (mac_len)
        memcpy(hat->mac, mac, mac_len);

    hat->mac_len = mac_len;
    hat->valid = TRUE;

    return TRUE;
}

/* same handle file as the HIDL backend */
static gboolean
fingerprint_aidl_gatekeeper_load_handle(guint32 uid, void** handle, guint32* handle_size)
{
    FILE* fp;
    gboolean success = FALSE;
    char* path = g_strdup_printf("/var/lib/biomd/handle-%u.blob", uid);

    *handle = NULL;
    *handle_size = 0;

    fp = fopen(path, "rb");
    if (fp) {
        long size;

        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (size > 0) {
            *handle = g_malloc(size);
            if (fread(*handle, 1, size, fp) == (size_t)size) {
                *handle_size = (guint32)size;
                success = TRUE;
            } else {
                g_free(*handle);
                *handle = NULL;
            }
        }
        fclose(fp);
    }

    g_free(path);
    return success;
}

static gboolean
fingerprint_aidl_gatekeeper_save_handle(guint32 uid, const void* data, guint32 size)
{
    FILE* fp;
    gboolean success = FALSE;
    char* path = g_strdup_printf("/var/lib/biomd/handle-%u.blob", uid);
    char* tmp = g_strdup_printf("%s.tmp", path);
    struct stat st = { 0 };

    if (stat("/var/lib/biomd", &st) == -1 && mkdir("/var/lib/biomd", 0700) == -1) {
        g_warning("Failed to create /var/lib/biomd");
        goto out;
    }

    fp = fopen(tmp, "wb");
    if (fp) {
        if (fwrite(data, 1, size, fp) == size)
            success = TRUE;
        fclose(fp);

        if (success && rename(tmp, path) != 0) {
            g_warning("Failed to store gatekeeper handle");
            success = FALSE;
        }
        if (!success)
            unlink(tmp);
        if (success)
            chmod(path, 0600);
    }

out:
    g_free(tmp);
    g_free(path);
    return success;
}

static void
fingerprint_aidl_gatekeeper_delete_user(BiomFingerprintAidl* self, guint32 uid)
{
    GBinderLocalRequest* req;
    GBinderWriter writer;

    if (!self->gatekeeper_client)
        return;

    /* void deleteUser(in int uid); */
    req = gbinder_client_new_request2(self->gatekeeper_client, GK_AIDL_DELETE_USER);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, uid);

    fingerprint_aidl_call_void(self->gatekeeper_client, GK_AIDL_DELETE_USER, req,
                               "IGatekeeper::deleteUser");
}

static gboolean
fingerprint_aidl_gatekeeper_enroll(BiomFingerprintAidl* self, guint32 uid, const char* password)
{
    GBinderLocalRequest* req;
    GBinderRemoteReply* reply;
    GBinderWriter writer;
    GBinderReader reader;
    int status = GBINDER_STATUS_FAILED;
    gboolean success = FALSE;
    gint32 parcelable_size = 0, status_code = 0, timeout_ms = 0;
    gint64 secure_user_id = 0;
    const void* data;
    gsize len = 0;

    if (!self->gatekeeper_client)
        return FALSE;

    /* GatekeeperEnrollResponse enroll(in int uid, in byte[] currentPasswordHandle,
     *     in byte[] currentPassword, in byte[] desiredPassword); */
    req = gbinder_client_new_request2(self->gatekeeper_client, GK_AIDL_ENROLL);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, uid);
    fingerprint_aidl_append_byte_array(&writer, NULL, 0);
    fingerprint_aidl_append_byte_array(&writer, NULL, 0);
    fingerprint_aidl_append_byte_array(&writer, password, strlen(password));

    reply = gbinder_client_transact_sync_reply(self->gatekeeper_client, GK_AIDL_ENROLL,
                                               req, &status);

    if (fingerprint_aidl_reply_ok(reply, status, &reader, "IGatekeeper::enroll")) {
        /* GatekeeperEnrollResponse { int statusCode; int timeoutMs;
         *                            long secureUserId; byte[] data; } */
        if (gbinder_reader_read_int32(&reader, &parcelable_size) &&
            gbinder_reader_read_int32(&reader, &status_code) &&
            gbinder_reader_read_int32(&reader, &timeout_ms) &&
            gbinder_reader_read_int64(&reader, &secure_user_id) &&
            (data = gbinder_reader_read_byte_array(&reader, &len)) != NULL &&
            len > 0) {

            if (status_code == GK_AIDL_STATUS_OK || status_code == GK_AIDL_STATUS_REENROLL)
                success = fingerprint_aidl_gatekeeper_save_handle(uid, data, (guint32)len);
            else
                g_warning("IGatekeeper::enroll refused with status %d (retry in %d ms)",
                          status_code, timeout_ms);
        } else {
            g_warning("IGatekeeper::enroll reply did not carry a password handle");
        }
    }

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(req);

    return success;
}

static gboolean
fingerprint_aidl_gatekeeper_verify(BiomFingerprintAidl* self, guint32 uid, guint64 challenge,
                                   const void* handle, guint32 handle_size,
                                   const char* password, AidlHardwareAuthToken* auth_token)
{
    GBinderLocalRequest* req;
    GBinderRemoteReply* reply;
    GBinderWriter writer;
    GBinderReader reader;
    int status = GBINDER_STATUS_FAILED;
    gboolean success = FALSE;
    gint32 parcelable_size = 0, status_code = 0, timeout_ms = 0;

    if (!self->gatekeeper_client)
        return FALSE;

    /* GatekeeperVerifyResponse verify(in int uid, in long challenge,
     *     in byte[] enrolledPasswordHandle, in byte[] providedPassword); */
    req = gbinder_client_new_request2(self->gatekeeper_client, GK_AIDL_VERIFY);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, uid);
    gbinder_writer_append_int64(&writer, challenge);
    fingerprint_aidl_append_byte_array(&writer, handle, handle_size);
    fingerprint_aidl_append_byte_array(&writer, password, strlen(password));

    reply = gbinder_client_transact_sync_reply(self->gatekeeper_client, GK_AIDL_VERIFY,
                                               req, &status);

    if (fingerprint_aidl_reply_ok(reply, status, &reader, "IGatekeeper::verify")) {
        /* GatekeeperVerifyResponse { int statusCode; int timeoutMs;
         *                            HardwareAuthToken hardwareAuthToken; } */
        if (gbinder_reader_read_int32(&reader, &parcelable_size) &&
            gbinder_reader_read_int32(&reader, &status_code) &&
            gbinder_reader_read_int32(&reader, &timeout_ms)) {

            if (status_code == GK_AIDL_STATUS_OK || status_code == GK_AIDL_STATUS_REENROLL) {
                success = fingerprint_aidl_read_auth_token(&reader, auth_token);
                if (!success)
                    g_warning("IGatekeeper::verify returned an unreadable HardwareAuthToken");
            } else {
                g_warning("IGatekeeper::verify refused with status %d (retry in %d ms)",
                          status_code, timeout_ms);
            }
        } else {
            g_warning("IGatekeeper::verify reply was malformed");
        }
    }

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(req);

    return success;
}

static int
fingerprint_aidl_handle_acquired(BiomFingerprintAidl* self, GBinderReader* reader)
{
    gint32 info, vendor_code;

    /* void onAcquired(in AcquiredInfo info, in int vendorCode); */
    if (gbinder_reader_read_int32(reader, &info) &&
        gbinder_reader_read_int32(reader, &vendor_code)) {

        g_debug("onAcquired info: %d, vendor_code: %d", info, vendor_code);

        if (self->callbacks.acquired)
            self->callbacks.acquired(self->user_data,
                                     fingerprint_aidl_map_acquired(info),
                                     (guint32)vendor_code);

        return GBINDER_STATUS_OK;
    }

    g_warning("Failed to parse ISessionCallback::onAcquired payload");
    return GBINDER_STATUS_FAILED;
}

static int
fingerprint_aidl_handle_error(BiomFingerprintAidl* self, GBinderReader* reader)
{
    gint32 error, vendor_code;

    /* void onError(in Error error, in int vendorCode); */
    if (gbinder_reader_read_int32(reader, &error) &&
        gbinder_reader_read_int32(reader, &vendor_code)) {

        g_debug("onError error: %d, vendor_code: %d", error, vendor_code);

        if (self->callbacks.error)
            self->callbacks.error(self->user_data,
                                  fingerprint_aidl_map_error(error),
                                  (guint32)vendor_code);

        return GBINDER_STATUS_OK;
    }

    g_warning("Failed to parse ISessionCallback::onError payload");
    return GBINDER_STATUS_FAILED;
}

static int
fingerprint_aidl_handle_enrollment_progress(BiomFingerprintAidl* self, GBinderReader* reader)
{
    gint32 enrollment_id, remaining;

    /* void onEnrollmentProgress(in int enrollmentId, int remaining); */
    if (gbinder_reader_read_int32(reader, &enrollment_id) &&
        gbinder_reader_read_int32(reader, &remaining)) {

        g_debug("onEnrollmentProgress enrollment_id: %d, remaining: %d",
                enrollment_id, remaining);

        if (self->callbacks.enroll_result)
            self->callbacks.enroll_result(self->user_data, (guint32)enrollment_id,
                                          0 /* no group on AIDL */, (guint32)remaining);

        return GBINDER_STATUS_OK;
    }

    g_warning("Failed to parse ISessionCallback::onEnrollmentProgress payload");
    return GBINDER_STATUS_FAILED;
}

static int
fingerprint_aidl_handle_authentication_succeeded(BiomFingerprintAidl* self, GBinderReader* reader)
{
    gint32 enrollment_id;

    /* void onAuthenticationSucceeded(in int enrollmentId, in HardwareAuthToken hat); */
    if (gbinder_reader_read_int32(reader, &enrollment_id)) {
        g_debug("onAuthenticationSucceeded enrollment_id: %d", enrollment_id);

        if (self->callbacks.authenticated)
            self->callbacks.authenticated(self->user_data, (guint32)enrollment_id, 0);

        return GBINDER_STATUS_OK;
    }

    g_warning("Failed to parse ISessionCallback::onAuthenticationSucceeded payload");
    return GBINDER_STATUS_FAILED;
}

static int
fingerprint_aidl_handle_authentication_failed(BiomFingerprintAidl* self)
{
    g_debug("onAuthenticationFailed");

    /* reported like HIDL does, as a non fatal UNABLE_TO_PROCESS */
    if (self->callbacks.error)
        self->callbacks.error(self->user_data, FINGERPRINT_ERROR_UNABLE_TO_PROCESS, 0);

    return GBINDER_STATUS_OK;
}

/*
 * AIDL reports all ids in one array, HIDL one per callback with a remaining
 * count. replay the array that way, with one call for an empty array.
 */
static int
fingerprint_aidl_replay_id_array(BiomFingerprintAidl* self, GBinderReader* reader,
                                 void (*cb)(gpointer, guint32, guint32, guint32),
                                 const char* what)
{
    gint32 count = 0;
    gint32 i;

    if (!gbinder_reader_read_int32(reader, &count)) {
        g_warning("Failed to parse %s payload", what);
        return GBINDER_STATUS_FAILED;
    }

    /* null array is -1 */
    if (count < 0)
        count = 0;

    g_debug("%s: %d enrollment(s)", what, count);

    if (count == 0) {
        if (cb)
            cb(self->user_data, 0, 0, 0);
        return GBINDER_STATUS_OK;
    }

    for (i = 0; i < count; i++) {
        gint32 id;

        if (!gbinder_reader_read_int32(reader, &id)) {
            g_warning("Failed to parse %s entry %d", what, i);
            return GBINDER_STATUS_FAILED;
        }

        if (cb)
            cb(self->user_data, (guint32)id, 0, (guint32)(count - 1 - i));
    }

    return GBINDER_STATUS_OK;
}

static GBinderLocalReply*
fingerprint_aidl_session_callback(GBinderLocalObject* obj, GBinderRemoteRequest* req,
                                  guint code, guint flags, int* status, void* user_data)
{
    BiomFingerprintAidl* self = (BiomFingerprintAidl*) user_data;
    const char* iface = gbinder_remote_request_interface(req);

    (void) flags;

    if (!g_strcmp0(iface, FP_AIDL_CALLBACK)) {
        GBinderReader reader;
        gbinder_remote_request_init_reader(req, &reader);

        switch (code) {
        case CB_ON_ACQUIRED:
            *status = fingerprint_aidl_handle_acquired(self, &reader);
            break;
        case CB_ON_ERROR:
            *status = fingerprint_aidl_handle_error(self, &reader);
            break;
        case CB_ON_ENROLLMENT_PROGRESS:
            *status = fingerprint_aidl_handle_enrollment_progress(self, &reader);
            break;
        case CB_ON_AUTHENTICATION_SUCCEEDED:
            *status = fingerprint_aidl_handle_authentication_succeeded(self, &reader);
            break;
        case CB_ON_AUTHENTICATION_FAILED:
            *status = fingerprint_aidl_handle_authentication_failed(self);
            break;
        case CB_ON_ENROLLMENTS_ENUMERATED:
            *status = fingerprint_aidl_replay_id_array(self, &reader,
                self->callbacks.enumerate, "onEnrollmentsEnumerated");
            break;
        case CB_ON_ENROLLMENTS_REMOVED:
            *status = fingerprint_aidl_replay_id_array(self, &reader,
                self->callbacks.removed, "onEnrollmentsRemoved");
            break;
        case CB_ON_LOCKOUT_TIMED:
        case CB_ON_LOCKOUT_PERMANENT:
            /* lockout is part of Error on HIDL */
            g_debug("onLockout (code %u)", code);
            if (self->callbacks.error)
                self->callbacks.error(self->user_data, FINGERPRINT_ERROR_LOCKOUT, 0);
            *status = GBINDER_STATUS_OK;
            break;
        case CB_ON_CHALLENGE_GENERATED:
        case CB_ON_CHALLENGE_REVOKED:
        case CB_ON_LOCKOUT_CLEARED:
        case CB_ON_INTERACTION_DETECTED:
        case CB_ON_AUTHENTICATOR_ID_RETRIEVED:
        case CB_ON_AUTHENTICATOR_ID_INVALIDATED:
        case CB_ON_SESSION_CLOSED:
            g_debug("ISessionCallback %u acknowledged", code);
            *status = GBINDER_STATUS_OK;
            break;
        default:
            g_warning("ISessionCallback %u unknown callback", code);
            *status = GBINDER_STATUS_FAILED;
            break;
        }
    } else {
        g_warning("Session callback event unhandled: %s %u", iface, code);
        *status = GBINDER_STATUS_FAILED;
    }

    /* all ISessionCallback methods return void */
    return (*status == GBINDER_STATUS_OK) ? gbinder_local_reply_append_int32
        (gbinder_local_object_new_reply(obj), 0) : NULL;
}

/* only reads the sensor id of the first SensorProps.commonProps */
static gint32
fingerprint_aidl_get_sensor_id(BiomFingerprintAidl* self)
{
    GBinderLocalRequest* req;
    GBinderRemoteReply* reply;
    GBinderReader reader;
    int status = GBINDER_STATUS_FAILED;
    gint32 sensor_id = 0;
    gint32 count = 0, props_size = 0, common_size = 0;

    req = gbinder_client_new_request2(self->fingerprint_client, FP_GET_SENSOR_PROPS);
    reply = gbinder_client_transact_sync_reply(self->fingerprint_client,
                                                FP_GET_SENSOR_PROPS, req, &status);

    if (fingerprint_aidl_reply_ok(reply, status, &reader, "IFingerprint::getSensorProps")) {
        if (gbinder_reader_read_int32(&reader, &count) && count > 0 &&
            gbinder_reader_read_int32(&reader, &props_size) &&
            gbinder_reader_read_int32(&reader, &common_size) &&
            gbinder_reader_read_int32(&reader, &sensor_id)) {
            g_debug("IFingerprint::getSensorProps reported %d sensor(s), first id %d",
                    count, sensor_id);
        } else {
            g_warning("Could not read a sensor id out of getSensorProps, assuming 0");
            sensor_id = 0;
        }
    } else {
        g_warning("IFingerprint::getSensorProps failed, assuming sensor id 0");
    }

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(req);

    return sensor_id;
}

static gboolean
fingerprint_aidl_create_session(BiomFingerprintAidl* self)
{
    GBinderLocalRequest* req;
    GBinderRemoteReply* reply;
    GBinderWriter writer;
    GBinderReader reader;
    int status = GBINDER_STATUS_FAILED;
    gboolean success = FALSE;

    /* ISession createSession(in int sensorId, in int userId, in ISessionCallback cb); */
    req = gbinder_client_new_request2(self->fingerprint_client, FP_CREATE_SESSION);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, self->sensor_id);
    gbinder_writer_append_int32(&writer, 0 /* userId */);
    gbinder_writer_append_local_object(&writer, self->session_callback);

    reply = gbinder_client_transact_sync_reply(self->fingerprint_client,
                                                FP_CREATE_SESSION, req, &status);

    if (fingerprint_aidl_reply_ok(reply, status, &reader, "IFingerprint::createSession")) {
        self->session_remote = gbinder_reader_read_object(&reader);
        if (self->session_remote) {
            self->session_client = gbinder_client_new(self->session_remote, FP_AIDL_SESSION);
            success = (self->session_client != NULL);
        } else {
            g_warning("IFingerprint::createSession returned no session object");
        }
    }

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(req);

    return success;
}

static void
fingerprint_aidl_take_cancel_signal(BiomFingerprintAidl* self, GBinderReader* reader)
{
    GBinderRemoteObject* obj;

    g_clear_pointer(&self->cancel_client, gbinder_client_unref);
    g_clear_pointer(&self->cancel_remote, gbinder_remote_object_unref);

    obj = gbinder_reader_read_object(reader);
    if (obj) {
        self->cancel_remote = obj;
        self->cancel_client = gbinder_client_new(obj, FP_AIDL_CANCEL);
    } else {
        g_debug("Operation returned no cancellation signal; cancel will be a no-op");
    }
}

BiomFingerprintAidl*
fingerprint_aidl_init(const FingerprintAidlCallbacks* callbacks, gpointer user_data)
{
    GBinderServiceManager* sm;
    GBinderRemoteObject* fingerprint_remote;
    BiomFingerprintAidl* self;

    g_debug("Initializing fingerprint AIDL interface");

    sm = gbinder_servicemanager_new(BINDER_DEVICE);
    if (!sm) {
        g_warning("Failed to create gbinder service manager for %s", BINDER_DEVICE);
        return NULL;
    }

    fingerprint_remote = gbinder_servicemanager_get_service_sync(sm, FP_AIDL_SERVICE, NULL);
    if (!fingerprint_remote) {
        g_debug("%s is not registered", FP_AIDL_SERVICE);
        gbinder_servicemanager_unref(sm);
        return NULL;
    }

    self = g_new0(BiomFingerprintAidl, 1);
    self->sm = sm;
    /* autoreleased, take our own reference */
    self->fingerprint_remote = gbinder_remote_object_ref(fingerprint_remote);
    self->available = FALSE;

    if (callbacks)
        self->callbacks = *callbacks;

    self->user_data = user_data;

    self->fingerprint_client = gbinder_client_new(self->fingerprint_remote, FP_AIDL);
    if (!self->fingerprint_client) {
        g_warning("Failed to create fingerprint client");
        fingerprint_aidl_cleanup(self);
        return NULL;
    }

    /* the HAL is @VintfStability and requires the same of the callback */
    self->session_callback = gbinder_servicemanager_new_local_object(
        sm, FP_AIDL_CALLBACK, fingerprint_aidl_session_callback, self);
    if (!self->session_callback) {
        g_warning("Failed to create session callback object");
        fingerprint_aidl_cleanup(self);
        return NULL;
    }
    gbinder_local_object_set_stability(self->session_callback, GBINDER_STABILITY_VINTF);

    self->sensor_id = fingerprint_aidl_get_sensor_id(self);

    if (!fingerprint_aidl_create_session(self)) {
        g_warning("Failed to open an AIDL fingerprint session");
        fingerprint_aidl_cleanup(self);
        return NULL;
    }

    /* only needed for enrollment */
    self->gatekeeper_remote = gbinder_remote_object_ref(
        gbinder_servicemanager_get_service_sync(sm, GK_AIDL_SERVICE, NULL));
    if (self->gatekeeper_remote) {
        self->gatekeeper_client = gbinder_client_new(self->gatekeeper_remote, GK_AIDL);
    } else {
        g_warning("%s is not registered; enrollment may be refused by the HAL",
                  GK_AIDL_SERVICE);
    }

    self->available = TRUE;
    g_debug("Fingerprint AIDL initialization complete, sensor id: %d", self->sensor_id);

    return self;
}

gboolean
fingerprint_aidl_is_available(BiomFingerprintAidl* self)
{
    return self && self->available;
}

gboolean
fingerprint_aidl_setup(BiomFingerprintAidl* self)
{
    GBinderLocalRequest* req;

    if (!self || !self->available)
        return FALSE;

    req = gbinder_client_new_request2(self->session_client, SESSION_ENUMERATE_ENROLLMENTS);
    return fingerprint_aidl_call_void(self->session_client, SESSION_ENUMERATE_ENROLLMENTS,
                                      req, "ISession::enumerateEnrollments");
}

gboolean
fingerprint_aidl_perform_enrollment(BiomFingerprintAidl* self, const gchar* password,
                                    guint32 timeout_sec)
{
    GBinderLocalRequest* req;
    GBinderRemoteReply* reply;
    GBinderWriter writer;
    GBinderReader reader;
    int status = GBINDER_STATUS_FAILED;
    AidlHardwareAuthToken auth_token;
    gboolean have_token = FALSE;
    gboolean success = FALSE;
    void* handle = NULL;
    guint32 handle_size = 0;

    if (!self || !self->available) {
        g_warning("Fingerprint AIDL interface not available for enrollment");
        return FALSE;
    }

    /* AIDL enroll has no timeout */
    (void) timeout_sec;

    g_debug("Starting AIDL fingerprint enrollment sequence");

    memset(&auth_token, 0, sizeof(auth_token));

    if (!password)
        password = "default_password";

    if (self->gatekeeper_client) {
        if (!fingerprint_aidl_gatekeeper_load_handle(0, &handle, &handle_size)) {
            g_debug("No existing handle found, enrolling password first");
            fingerprint_aidl_gatekeeper_delete_user(self, 0);
            fingerprint_aidl_gatekeeper_enroll(self, 0, password);
            fingerprint_aidl_gatekeeper_load_handle(0, &handle, &handle_size);
        }

        if (handle) {
            /* the challenge is not checked at enroll time, so use 0 rather
             * than waiting for generateChallenge() */
            have_token = fingerprint_aidl_gatekeeper_verify(self, 0, 0, handle, handle_size,
                                                            password, &auth_token);
            g_free(handle);
        }

        if (!have_token)
            g_warning("Could not mint an auth token; enrolling with an empty one");
    }

    /* ICancellationSignal enroll(in HardwareAuthToken hat); */
    req = gbinder_client_new_request2(self->session_client, SESSION_ENROLL);
    gbinder_local_request_init_writer(req, &writer);
    fingerprint_aidl_write_auth_token(&writer, have_token ? &auth_token : NULL);

    reply = gbinder_client_transact_sync_reply(self->session_client, SESSION_ENROLL,
                                                req, &status);

    if (fingerprint_aidl_reply_ok(reply, status, &reader, "ISession::enroll")) {
        fingerprint_aidl_take_cancel_signal(self, &reader);
        success = TRUE;
    }

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(req);

    return success;
}

gboolean
fingerprint_aidl_perform_authentication(BiomFingerprintAidl* self)
{
    GBinderLocalRequest* req;
    GBinderRemoteReply* reply;
    GBinderWriter writer;
    GBinderReader reader;
    int status = GBINDER_STATUS_FAILED;
    gboolean success = FALSE;

    if (!self || !self->available) {
        g_warning("Fingerprint AIDL interface not available for authentication");
        return FALSE;
    }

    /* ICancellationSignal authenticate(in long operationId); */
    req = gbinder_client_new_request2(self->session_client, SESSION_AUTHENTICATE);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int64(&writer, 0);

    reply = gbinder_client_transact_sync_reply(self->session_client, SESSION_AUTHENTICATE,
                                                req, &status);

    if (fingerprint_aidl_reply_ok(reply, status, &reader, "ISession::authenticate")) {
        fingerprint_aidl_take_cancel_signal(self, &reader);
        success = TRUE;
    }

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(req);

    return success;
}

gboolean
fingerprint_aidl_cancel_operation(BiomFingerprintAidl* self)
{
    GBinderLocalRequest* req;
    gboolean ok;

    if (!self || !self->available)
        return FALSE;

    if (!self->cancel_client) {
        g_debug("No operation to cancel");
        return FALSE;
    }

    /* void cancel(); */
    req = gbinder_client_new_request2(self->cancel_client, CANCELLATION_CANCEL);
    ok = fingerprint_aidl_call_void(self->cancel_client, CANCELLATION_CANCEL, req,
                                    "ICancellationSignal::cancel");

    g_clear_pointer(&self->cancel_client, gbinder_client_unref);
    g_clear_pointer(&self->cancel_remote, gbinder_remote_object_unref);

    return ok;
}

gboolean
fingerprint_aidl_remove_fingerprint(BiomFingerprintAidl* self, guint32 finger_id)
{
    GBinderLocalRequest* req;
    GBinderWriter writer;

    if (!self || !self->available)
        return FALSE;

    /* void removeEnrollments(in int[] enrollmentIds); */
    req = gbinder_client_new_request2(self->session_client, SESSION_REMOVE_ENROLLMENTS);
    gbinder_local_request_init_writer(req, &writer);
    gbinder_writer_append_int32(&writer, 1);
    gbinder_writer_append_int32(&writer, (gint32)finger_id);

    return fingerprint_aidl_call_void(self->session_client, SESSION_REMOVE_ENROLLMENTS,
                                      req, "ISession::removeEnrollments");
}

void
fingerprint_aidl_cleanup(BiomFingerprintAidl* self)
{
    if (!self)
        return;

    self->available = FALSE;

    if (self->session_client) {
        /* void close(); */
        GBinderLocalRequest* req = gbinder_client_new_request2(self->session_client,
                                                               SESSION_CLOSE);
        fingerprint_aidl_call_void(self->session_client, SESSION_CLOSE, req,
                                   "ISession::close");
    }

    g_clear_pointer(&self->cancel_client, gbinder_client_unref);
    g_clear_pointer(&self->cancel_remote, gbinder_remote_object_unref);
    g_clear_pointer(&self->session_client, gbinder_client_unref);
    g_clear_pointer(&self->session_remote, gbinder_remote_object_unref);
    g_clear_pointer(&self->session_callback, gbinder_local_object_unref);
    g_clear_pointer(&self->gatekeeper_client, gbinder_client_unref);
    g_clear_pointer(&self->gatekeeper_remote, gbinder_remote_object_unref);
    g_clear_pointer(&self->fingerprint_client, gbinder_client_unref);
    g_clear_pointer(&self->fingerprint_remote, gbinder_remote_object_unref);
    g_clear_pointer(&self->sm, gbinder_servicemanager_unref);

    g_free(self);
}
