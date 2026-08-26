/* mka_wolfmka.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Adapter that runs the wolfDen wolfMKA KaY (MACsec Key Agreement control
 * plane) as a wolfIP MKA backend, driving wolfIP's software SecY
 * (macsec_secy.c / macsec_sa.c) as the data plane. Built when WOLFMKA_DIR
 * points at a local wolfMKA clone (https://github.com/wolfSSL/wolfDen/tree/main/mka).
 *
 * The adapter wires three seams: wolfMKA's transmit callback to a wolfIP L2
 * send, wolfMKA's MkaSecyOps to the caller's software SecY transmit/receive
 * Secure Channels, and wolfMKA's RNG/CMAC workspace pools to wolfSSL. The
 * integrator feeds received EAPOL-MKA frames to mka_wolfmka_rx() and calls
 * mka_wolfmka_tick() each poll iteration.
 */

#ifndef WOLFIP_MKA_WOLFMKA_H
#define WOLFIP_MKA_WOLFMKA_H

#include <stdint.h>
#include <stddef.h>

#include "macsec_sa.h"
#include <wolfmka/mka_kay.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Transmit an EAPOL-MKA frame (full L2 frame, dst = 01:80:C2:00:00:03).
 * Returns 0 on success. */
typedef int (*mka_wolfmka_send_fn)(void *ctx, const uint8_t *frame, size_t len);

/* One wolfMKA-backed MKA participant plus the wolfIP glue. Statically
 * allocatable. The tx/rx Secure Channels are owned by the caller (the wolfIP
 * datapath); wolfMKA installs SAKs into them through the SecY callbacks. */
struct mka_wolfmka {
    MkaParticipant       p;
    MkaRandom           *rng;
    MkaCmacCtx          *cmac;
    struct macsec_tx_sc *tx;      /* software SecY transmit channel  */
    struct macsec_rx_sc *rx;      /* software SecY receive channel    */
    mka_wolfmka_send_fn  send;
    void                *send_ctx;
    size_t               conf_offset;  /* 0/30/50 octets, from set_cipher_suite */
    size_t               sak_len;   /* key length the cipher suite implies, or
                                     * 0 before set_cipher_suite runs      */
    uint32_t             replay_window; /* frames of reorder tolerated      */
    uint8_t              src_mac[6];    /* our MAC (SCI[0:6]) for the L2 header */
    uint8_t              encrypt;       /* 0 = integrity only               */
    uint8_t              replay_protect;
    uint8_t              installed;     /* a transmit SA is protecting       */
};

/* Initialise with a pre-shared CAK/CKN. sci is our Secure Channel Identifier
 * (MAC || port). priority is the Key Server priority; key_server_capable lets
 * us be elected. tx/rx are the caller's software SecY channels. Returns 0 on
 * success, negative on error. */
int mka_wolfmka_init_psk(struct mka_wolfmka *m,
                         mka_wolfmka_send_fn send, void *send_ctx,
                         const uint8_t *cak, size_t cak_len,
                         const uint8_t *ckn, size_t ckn_len,
                         const uint8_t sci[8], uint8_t priority,
                         uint8_t key_server_capable, size_t sak_len,
                         struct macsec_tx_sc *tx, struct macsec_rx_sc *rx);

/* Set the receive replay policy. 802.1AE treats the replay window as a
 * managed object, so it is configurable rather than fixed: the default is
 * strict monotonic ordering (protect on, window 0), which is right for a
 * point-to-point link but drops every out-of-order frame on a path that
 * reorders - a multi-queue NIC, a switch hashing per flow, a bridged path.
 * window is the number of frames of reorder tolerated below the highest
 * accepted packet number. Note the window is a sliding low-water mark rather
 * than a bitmap, so a duplicate inside a non-zero window is accepted (802.1AE
 * permits this). Call before the CA converges; it applies to SAs installed
 * from then on. Returns 0 on success. */
int mka_wolfmka_set_replay(struct mka_wolfmka *m, uint8_t replay_protect,
                           uint32_t window);

/* Initialise from an EAP-TLS MSK. Derives the CAK and CKN (802.1X-2010 9.3.1)
 * from the MSK, the two peer MAC addresses, and the EAP Session-Id using
 * wolfIP's key hierarchy (macsec_crypto.c), then behaves as
 * mka_wolfmka_init_psk. cak_len is 16 or 32. Returns 0 on success.
 *
 * NOTE: the CAK/CKN-from-MSK context ordering is not yet cross-checked against
 * wpa_supplicant EAP-MKA; two wolfIP/wolfMKA peers sharing an MSK agree, but
 * interop with wpa's EAP path is unverified (see macsec_crypto.h). */
int mka_wolfmka_init_eap(struct mka_wolfmka *m,
                         mka_wolfmka_send_fn send, void *send_ctx,
                         const uint8_t *msk, size_t msk_len, size_t cak_len,
                         const uint8_t *eap_session_id, size_t session_id_len,
                         const uint8_t peer_mac[6], const uint8_t auth_mac[6],
                         const uint8_t sci[8], uint8_t priority,
                         uint8_t key_server_capable,
                         struct macsec_tx_sc *tx, struct macsec_rx_sc *rx);

/* Feed a received EAPOL-MKA frame (full L2 frame). Returns 0 on success. */
int mka_wolfmka_rx(struct mka_wolfmka *m, const uint8_t *frame, size_t len,
                   uint32_t now_ms);

/* Periodic service: runs timers, may transmit MKPDUs and install SAKs. */
int mka_wolfmka_tick(struct mka_wolfmka *m, uint32_t now_ms);

/* 1 once a transmit SA has been agreed and enabled (for status / tests). */
int mka_wolfmka_installed(const struct mka_wolfmka *m);

/* Tear down and zeroise. */
void mka_wolfmka_free(struct mka_wolfmka *m);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_MKA_WOLFMKA_H */
