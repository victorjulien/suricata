/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 *
 */

#ifndef SURICATA_APP_LAYER_SSL_H
#define SURICATA_APP_LAYER_SSL_H

#include "util-ja3.h"
#include "rust.h"

enum TlsFrameTypes {
    TLS_FRAME_PDU = 0, /**< whole PDU, so header + data */
    TLS_FRAME_HDR,     /**< only header portion */
    TLS_FRAME_DATA,    /**< only data portion */
    TLS_FRAME_ALERT_DATA,
    TLS_FRAME_HB_DATA,
    TLS_FRAME_SSLV2_HDR,
    TLS_FRAME_SSLV2_PDU,
};

enum {
    /* TLS protocol messages */
    TLS_DECODER_EVENT_INVALID_SSLV2_HEADER,
    TLS_DECODER_EVENT_INVALID_TLS_HEADER,
    TLS_DECODER_EVENT_INVALID_RECORD_VERSION,
    TLS_DECODER_EVENT_INVALID_RECORD_TYPE,
    TLS_DECODER_EVENT_INVALID_RECORD_LENGTH,
    TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE,
    TLS_DECODER_EVENT_HEARTBEAT,
    TLS_DECODER_EVENT_INVALID_HEARTBEAT,
    TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT,
    TLS_DECODER_EVENT_DATALEAK_HEARTBEAT_MISMATCH,
    TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH,
    TLS_DECODER_EVENT_MULTIPLE_SNI_EXTENSIONS,
    TLS_DECODER_EVENT_INVALID_SNI_TYPE,
    TLS_DECODER_EVENT_INVALID_SNI_LENGTH,
    TLS_DECODER_EVENT_TOO_MANY_RECORDS_IN_PACKET,
    TLS_DECODER_EVENT_INVALID_ALERT,
    /* Certificates decoding messages */
    TLS_DECODER_EVENT_INVALID_CERTIFICATE,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_VERSION,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_SERIAL,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_ALGORITHMIDENTIFIER,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_X509NAME,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_DATE,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_EXTENSIONS,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_DER,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_SUBJECT,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_ISSUER,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_VALIDITY,
    TLS_DECODER_EVENT_ERROR_MSG_ENCOUNTERED,
    TLS_DECODER_EVENT_INVALID_SSL_RECORD,
};

enum TlsStateClient {
    TLS_STATE_CLIENT_IN_PROGRESS = 0,
    TLS_STATE_CLIENT_HELLO_DONE,
    TLS_STATE_CLIENT_CERT_DONE,
    TLS_STATE_CLIENT_HANDSHAKE_DONE,
    TLS_STATE_CLIENT_FINISHED,
};

enum TlsStateServer {
    TLS_STATE_SERVER_IN_PROGRESS = 0,
    TLS_STATE_SERVER_HELLO,
    TLS_STATE_SERVER_CERT_DONE,
    TLS_STATE_SERVER_HELLO_DONE,
    TLS_STATE_SERVER_HANDSHAKE_DONE,
    TLS_STATE_SERVER_FINISHED,
};

/* Flag to indicate that server will now on send encrypted msgs */
#define SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC   BIT_U32(0)
/* Flag to indicate that client will now on send encrypted msgs */
#define SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC   BIT_U32(1)
#define SSL_AL_FLAG_CHANGE_CIPHER_SPEC          BIT_U32(2)

/* SSL related flags */
#define SSL_AL_FLAG_SSL_CLIENT_HS               BIT_U32(3)
#define SSL_AL_FLAG_SSL_SERVER_HS               BIT_U32(4)
#define SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY       BIT_U32(5)
#define SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED    BIT_U32(6)
#define SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED    BIT_U32(7)
#define SSL_AL_FLAG_SSL_NO_SESSION_ID           BIT_U32(8)

/* flags specific to detect-ssl-state keyword */
#define SSL_AL_FLAG_STATE_CLIENT_HELLO          BIT_U32(9)
#define SSL_AL_FLAG_STATE_SERVER_HELLO          BIT_U32(10)
#define SSL_AL_FLAG_STATE_CLIENT_KEYX           BIT_U32(11)
#define SSL_AL_FLAG_STATE_SERVER_KEYX           BIT_U32(12)
#define SSL_AL_FLAG_STATE_UNKNOWN               BIT_U32(13)

/* flags specific to HeartBeat state */
#define SSL_AL_FLAG_HB_INFLIGHT                 BIT_U32(15)
#define SSL_AL_FLAG_HB_CLIENT_INIT              BIT_U32(16)
#define SSL_AL_FLAG_HB_SERVER_INIT              BIT_U32(17)

/* Session resumed without a full handshake */
#define SSL_AL_FLAG_SESSION_RESUMED             BIT_U32(20)

/* Encountered a supported_versions extension in client hello */
#define SSL_AL_FLAG_CH_VERSION_EXTENSION        BIT_U32(21)

/* Log the session even without ever seeing a certificate. This is used
   to log TLSv1.3 sessions. */
#define SSL_AL_FLAG_LOG_WITHOUT_CERT            BIT_U32(22)

/* Encountered a early data extension in client hello. This extension is
   used by 0-RTT. */
#define SSL_AL_FLAG_EARLY_DATA                  BIT_U32(23)

/* flag to indicate that server random was filled */
#define TLS_TS_RANDOM_SET BIT_U32(24)

/* flag to indicate that client random was filled */
#define TLS_TC_RANDOM_SET BIT_U32(25)

#define SSL_AL_FLAG_NEED_CLIENT_CERT BIT_U32(26)

/* config flags */
#define SSL_TLS_LOG_PEM                         (1 << 0)

/* extensions */
#define SSL_EXTENSION_SNI                       0x0000
#define SSL_EXTENSION_ELLIPTIC_CURVES           0x000a
#define SSL_EXTENSION_EC_POINT_FORMATS          0x000b
#define SSL_EXTENSION_SIGNATURE_ALGORITHMS      0x000d
#define SSL_EXTENSION_ALPN                      0x0010
#define SSL_EXTENSION_SESSION_TICKET            0x0023
#define SSL_EXTENSION_EARLY_DATA                0x002a
#define SSL_EXTENSION_SUPPORTED_VERSIONS        0x002b

/* SNI types */
#define SSL_SNI_TYPE_HOST_NAME                  0

/* TLS random bytes for the sticky buffer */
#define TLS_RANDOM_LEN 32

typedef struct SSLCertsChain_ {
    uint8_t *cert_data;
    uint32_t cert_len;
    TAILQ_ENTRY(SSLCertsChain_) next;
} SSLCertsChain;

typedef struct SSLStateConnp_ {
    /* record length */
    uint32_t record_length;
    /* record length's length for SSLv2 */
    uint32_t record_lengths_length;

    /* offset of the beginning of the current message (including header) */
    uint32_t message_length;

    uint16_t version;
    uint8_t content_type;

    uint8_t handshake_type;

    /* the no of bytes processed in the currently parsed record */
    uint32_t bytes_processed;

    uint16_t session_id_length;

    uint8_t random[TLS_RANDOM_LEN];
    char *cert0_subject;
    char *cert0_issuerdn;
    char *cert0_serial;
    int64_t cert0_not_before;
    int64_t cert0_not_after;
    char *cert0_fingerprint;

    char **cert0_sans;
    uint16_t cert0_sans_len;
    /* ssl server name indication extension */
    char *sni;

    char *session_id;

    TAILQ_HEAD(, SSLCertsChain_) certs;

    uint8_t *certs_buffer;
    uint32_t certs_buffer_size;

    uint32_t cert_log_flag;

    JA3Buffer *ja3_str;
    char *ja3_hash;

    HandshakeParams *hs;

    /* handshake tls fragmentation buffer. Handshake messages can be fragmented over multiple
     * TLS records. */
    uint8_t *hs_buffer;
    uint8_t hs_buffer_message_type;
    uint32_t hs_buffer_message_size;
    uint32_t hs_buffer_size;   /**< allocation size */
    uint32_t hs_buffer_offset; /**< write offset */
} SSLStateConnp;

/**
 * \brief SSLv[2.0|3.[0|1|2|3]] state structure.
 *
 *        Structure to store the SSL state values.
 */
typedef struct SSLState_ {
    Flow *f;

    AppLayerStateData state_data;
    AppLayerTxData tx_data;

    /* holds some state flags we need */
    uint32_t flags;

    /* there might be a better place to store this*/
    uint32_t hb_record_len;

    uint16_t events;

    uint32_t current_flags;

    SSLStateConnp *curr_connp;

    enum TlsStateClient client_state;
    enum TlsStateServer server_state;

    SSLStateConnp client_connp;
    SSLStateConnp server_connp;
} SSLState;

void RegisterSSLParsers(void);
void SSLEnableJA3(void);
bool SSLJA3IsEnabled(void);
void SSLEnableJA4(void);
bool SSLJA4IsEnabled(void);

#endif /* SURICATA_APP_LAYER_SSL_H */
