/* mka_wolfmka.c
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

#include "mka_wolfmka.h"
#include "supplicant_features.h"
#include "macsec_crypto.h"      /* macsec_derive_cak / macsec_derive_ckn */
#include "wpa_crypto.h"         /* wpa_secure_zero */

#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include <wolfmka/mka_crypto.h>
#include <wolfmka/mka_secy.h>
#include <wolfmka/mka_types.h>

/* ---- MkaSecyOps over the wolfIP software SecY (macsec_secy/macsec_sa) ----
 *
 * wolfMKA calls set_cipher_suite before the SAs are installed, then
 * install_tx_sa / install_rx_sa with the agreed SAK, then enable_transmit /
 * enable_receive. The per-frame protect/validate stays in macsec_secy.c on the
 * wolfIP datapath; these callbacks only program the keys. */

static int secy_create_tx_sc(void *ctx, const uint8_t sci[MKA_SCI_LEN])
{
    (void)ctx; (void)sci;   /* the TX channel is set up on install_tx_sa */
    return 0;
}

static int secy_create_rx_sc(void *ctx, const uint8_t sci[MKA_SCI_LEN])
{
    (void)ctx; (void)sci;
    return 0;
}

/* Does a SAK about to be installed match the cipher suite in force?
 *
 * The suite fixes the key length, so a peer that negotiated GCM-AES-256 and a
 * SecY quietly running GCM-AES-128 is a downgrade nobody would notice: the
 * frames still authenticate, because the SAK length is what selects the AES
 * key size in the transform. m->sak_len is 0 until set_cipher_suite runs,
 * which means "whatever the Key Server distributes". */
static int mka_sak_len_agrees(const struct mka_wolfmka *m, size_t sak_len)
{
    return (m->sak_len == 0 || m->sak_len == sak_len);
}

static int secy_install_tx_sa(void *ctx, const uint8_t sci[MKA_SCI_LEN],
                              uint8_t an, uint32_t kn, const uint8_t *sak,
                              size_t sak_len)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;
    (void)kn;
    if (m->tx == NULL) {
        return -1;
    }
    if (!mka_sak_len_agrees(m, sak_len)) {
        return -1;
    }
    /* The key is installed but does not take the wire yet: wolfMKA moves
     * transmit onto it with enable_transmit() once every live peer reports
     * receiving on it, which is the make-before-break handover. */
    if (macsec_tx_sc_set_key(m->tx, sak, sak_len, sci, an, m->encrypt,
                             m->conf_offset, 1 /* include_sci */,
                             1 /* initial PN */) != 0) {
        return -1;
    }
    return 0;
}

static int secy_install_rx_sa(void *ctx, const uint8_t sci[MKA_SCI_LEN],
                              uint8_t an, uint32_t kn, const uint8_t *sak,
                              size_t sak_len)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;
    (void)kn;
    if (m->rx == NULL) {
        return -1;
    }
    if (!mka_sak_len_agrees(m, sak_len)) {
        return -1;
    }
    if (macsec_rx_sc_set_key(m->rx, sak, sak_len, sci, an,
                             m->replay_protect, m->replay_window,
                             m->conf_offset) != 0) {
        return -1;
    }
    return 0;
}

/* Move outbound protection onto (or off) the SA under an. This is what makes
 * mka_wolfmka_installed() mean "the link is protected": wolfMKA holds the
 * gate shut until every live peer has reported receiving on the key. */
static int secy_enable_transmit(void *ctx, uint8_t an, bool enable)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;

    if (m->tx == NULL) {
        return -1;
    }
    /* Turning an SA off that is already gone is not a failure - the wire is
     * off it either way - so only an enable has to find its SA. */
    if (macsec_tx_sc_set_active(m->tx, an, enable ? 1U : 0U) != 0 && enable) {
        return -1;
    }
    m->installed = m->tx->active ? 1U : 0U;
    return 0;
}

static int secy_enable_receive(void *ctx, const uint8_t sci[MKA_SCI_LEN],
                               uint8_t an, bool enable)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;
    (void)sci;

    if (m->rx == NULL) {
        return -1;
    }
    if (macsec_rx_sc_enable_sa(m->rx, an, enable ? 1U : 0U) != 0 && enable) {
        return -1;
    }
    return 0;
}

/* Tear down one Secure Association. wolfMKA selects the direction with the
 * SCI - NULL is the transmit SA, a peer SCI is that peer's receive SA (see
 * MkaSecyOps.delete_sa) - and names the key by its Association Number.
 *
 * The AN matters: wolfMKA runs make-before-break with two keys live, Latest
 * and Old, always on adjacent ANs. Retiring the Old key must not disturb the
 * Latest key that is carrying traffic, so the delete is scoped to the SA
 * holding that AN rather than scrubbing the whole channel. A delete for an AN
 * this data plane does not hold is not an error - the SA is already gone. */
static int secy_delete_sa(void *ctx, const uint8_t *sci, uint8_t an)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;

    if (sci == NULL) {
        if (m->tx != NULL) {
            (void)macsec_tx_sc_delete_sa(m->tx, an);
            /* Deleting the SA that was protecting leaves the link
             * unprotected; say so rather than letting an integrator poll a
             * stale flag and keep calling macsec_tx() on a dead channel. */
            m->installed = m->tx->active ? 1U : 0U;
        }
    }
    else if (m->rx != NULL) {
        (void)macsec_rx_sc_delete_sa(m->rx, an);
    }
    return 0;
}

static int secy_get_next_pn(void *ctx, uint8_t an, uint64_t *next_pn)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;
    uint32_t pn;

    if (m->tx == NULL || next_pn == NULL) {
        return -1;
    }
    if (macsec_tx_sc_next_pn(m->tx, an, &pn) != 0) {
        return -1;
    }
    *next_pn = (uint64_t)pn;
    return 0;
}

static int secy_set_lowest_pn(void *ctx, const uint8_t sci[MKA_SCI_LEN],
                              uint8_t an, uint64_t lowest_pn)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;
    (void)sci;

    if (m->rx == NULL) {
        return -1;
    }
    /* This data plane is 32-bit PN only (XPN is out of scope), so refuse a
     * value that does not fit rather than truncating it into a window that
     * would then accept frames it should reject. */
    if (lowest_pn > (uint64_t)MACSEC_PN_MAX) {
        return -1;
    }
    return (macsec_rx_sc_set_lowest_pn(m->rx, an, (uint32_t)lowest_pn) == 0)
               ? 0 : -1;
}

static int secy_set_cipher_suite(void *ctx, const uint8_t sci[MKA_SCI_LEN],
                                 uint64_t cipher_suite, uint32_t ssci,
                                 uint8_t confidentiality_offset)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;
    (void)sci; (void)ssci;

    /* Record the key length the negotiated suite implies so a SAK of the
     * wrong size is refused at install time (see mka_sak_len_agrees). The XPN
     * suites need 64-bit packet numbers, which this data plane does not
     * implement, so decline them rather than run them as their 32-bit
     * namesakes. */
    if (cipher_suite == 0 || cipher_suite == MKA_CIPHER_GCM_AES_128) {
        m->sak_len = MACSEC_KEY_LEN_128;
    }
    else if (cipher_suite == MKA_CIPHER_GCM_AES_256) {
        m->sak_len = MACSEC_KEY_LEN_256;
    }
    else {
        return -1;
    }

    if (confidentiality_offset == MKA_CONF_OFFSET_NONE) {
        m->encrypt = 0;             /* integrity only */
        m->conf_offset = 0;
    }
    else {
        m->encrypt = 1;
        if (confidentiality_offset == MKA_CONF_OFFSET_30) {
            m->conf_offset = 30;
        }
        else if (confidentiality_offset == MKA_CONF_OFFSET_50) {
            m->conf_offset = 50;
        }
        else {
            m->conf_offset = 0;
        }
    }
    return 0;
}

/* ---- event hooks (diagnostics, opt-in via WOLFIP_MKA_WOLFMKA_DEBUG) ---- */
#ifdef WOLFIP_MKA_WOLFMKA_DEBUG
static void ev_peer_added(void *ctx, const uint8_t mi[MKA_MI_LEN],
                          const uint8_t sci[MKA_SCI_LEN])
{ (void)ctx; (void)mi; (void)sci; fprintf(stderr, "[wolfmka] peer_added\n"); }
static void ev_peer_live(void *ctx, const uint8_t mi[MKA_MI_LEN])
{ (void)ctx; (void)mi; fprintf(stderr, "[wolfmka] peer_live\n"); }
static void ev_key_server_elected(void *ctx, const uint8_t sci[MKA_SCI_LEN],
                                  bool is_self)
{ (void)ctx; (void)sci; fprintf(stderr, "[wolfmka] key_server_elected self=%d\n", is_self); }
static void ev_sak_installed(void *ctx, uint32_t kn, uint8_t an,
                             uint64_t cipher_suite)
{ (void)ctx; (void)cipher_suite; fprintf(stderr, "[wolfmka] sak_installed kn=%u an=%u\n", kn, an); }
static void ev_auth_fail(void *ctx)
{ (void)ctx; fprintf(stderr, "[wolfmka] auth_fail (ICV)\n"); }

static void mka_wolfmka_event_ops(MkaEventOps *ev, struct mka_wolfmka *m)
{
    memset(ev, 0, sizeof(*ev));
    ev->peer_added         = ev_peer_added;
    ev->peer_live          = ev_peer_live;
    ev->key_server_elected = ev_key_server_elected;
    ev->sak_installed      = ev_sak_installed;
    ev->auth_fail          = ev_auth_fail;
    ev->ctx                = m;
}
#endif

static void mka_wolfmka_secy_ops(MkaSecyOps *ops, struct mka_wolfmka *m)
{
    memset(ops, 0, sizeof(*ops));
    ops->create_tx_sc     = secy_create_tx_sc;
    ops->create_rx_sc     = secy_create_rx_sc;
    ops->install_tx_sa    = secy_install_tx_sa;
    ops->install_rx_sa    = secy_install_rx_sa;
    ops->enable_transmit  = secy_enable_transmit;
    ops->enable_receive   = secy_enable_receive;
    ops->delete_sa        = secy_delete_sa;
    ops->get_next_pn      = secy_get_next_pn;
    ops->set_lowest_pn    = secy_set_lowest_pn;
    ops->set_cipher_suite = secy_set_cipher_suite;
    ops->ctx              = m;
}

/* ---- transmit callback bridge ----
 *
 * wolfMKA hands us the bare EAPOL-MKA PDU (from the EAPOL version octet); it
 * reconstructs the Ethernet DA/SA internally for the ICV. We prepend the L2
 * header (DA = PAE group, SA = our MAC, EtherType 0x888E) so the integrator's
 * send() and mka_wolfmka_rx() both deal in whole L2 frames. */

static const uint8_t MKA_PAE_GROUP[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 };
#define MKA_L2_HDR_LEN 14U

static int mka_wolfmka_send(void *ctx, const uint8_t *pdu, size_t len)
{
    struct mka_wolfmka *m = (struct mka_wolfmka *)ctx;
    /* Sized from wolfMKA's own MKPDU ceiling (itself derived from
     * MKA_MAX_PEERS) so raising the peer count cannot silently outgrow this
     * buffer and stop the participant transmitting. */
    uint8_t frame[MKA_L2_HDR_LEN + MKA_MKPDU_MAX_LEN];

    if (m->send == NULL || (MKA_L2_HDR_LEN + len) > sizeof(frame)) {
        return -1;
    }
    memcpy(frame, MKA_PAE_GROUP, 6);
    memcpy(frame + 6, m->src_mac, 6);
    frame[12] = 0x88;
    frame[13] = 0x8E;
    memcpy(frame + MKA_L2_HDR_LEN, pdu, len);
    return m->send(m->send_ctx, frame, MKA_L2_HDR_LEN + len);
}

/* ---- public API ---- */

int mka_wolfmka_init_psk(struct mka_wolfmka *m,
                         mka_wolfmka_send_fn send, void *send_ctx,
                         const uint8_t *cak, size_t cak_len,
                         const uint8_t *ckn, size_t ckn_len,
                         const uint8_t sci[8], uint8_t priority,
                         uint8_t key_server_capable, size_t sak_len,
                         struct macsec_tx_sc *tx, struct macsec_rx_sc *rx)
{
    MkaParticipantConfig cfg;
    int                  ret;

    if (m == NULL || cak == NULL || ckn == NULL || sci == NULL) {
        return -1;
    }
    /* A CAK is 128 or 256 bits (802.1X-2010 6.2.1). Checking only the upper
     * bound would let a truncated key through to be copied into a fixed-size
     * buffer and used to derive the KEK and ICK from partly uninitialised
     * material; fail at the API edge rather than rely on the library to
     * reject it downstream. */
    if (cak_len != MACSEC_KEY_LEN_128 && cak_len != MACSEC_KEY_LEN_256) {
        return -1;
    }
    if (ckn_len == 0 || ckn_len > MKA_MAX_CKN_LEN) {
        return -1;
    }
    if (sak_len != MACSEC_KEY_LEN_128 && sak_len != MACSEC_KEY_LEN_256) {
        return -1;
    }

    memset(m, 0, sizeof(*m));
    m->send     = send;
    m->send_ctx = send_ctx;
    m->tx       = tx;
    m->rx       = rx;
    /* The channels are caller-owned storage but this participant is what
     * programs them, so start them from a known state rather than trusting
     * whatever the integrator's struct happened to hold. */
    macsec_tx_sc_init(tx);
    macsec_rx_sc_init(rx);
    memcpy(m->src_mac, sci, 6);      /* L2 source address for outbound frames */
    m->encrypt  = 1;                 /* default; refined by set_cipher_suite */
    m->conf_offset = 0;
    m->sak_len  = 0;                 /* set by set_cipher_suite */
    /* Strict ordering by default: correct on a point-to-point link and the
     * safest starting point. mka_wolfmka_set_replay() widens it for a path
     * that reorders (a multi-queue NIC, a switch hashing per flow). */
    m->replay_protect = 1;
    m->replay_window  = 0;

    /* Both workspaces are mandatory. The RNG is not optional decoration: MKA
     * draws the Member Identifier, the Key Server nonce and - when this
     * participant is elected - the SAK itself from it. Note the default
     * WOLFMKA_RANDOM_POOL_SIZE (and CMAC pool) is 1, so a second participant
     * in one process needs the pool raised at build time; that shows up here
     * as a NULL rather than as weak key material later. */
    m->rng  = wm_Crypto_RandomInit();
    m->cmac = wm_Crypto_CmacInit();
    if (m->rng == NULL || m->cmac == NULL) {
        mka_wolfmka_free(m);
        return -1;
    }

    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.cak.cak, cak, cak_len);
    cfg.cak.cak_len = cak_len;
    memcpy(cfg.cak.ckn, ckn, ckn_len);
    cfg.cak.ckn_len = ckn_len;
    memcpy(cfg.sci, sci, MKA_SCI_LEN);
    cfg.cipher_suite = 0;            /* 0 => GCM-AES-128 default */
    cfg.sak_len = (uint8_t)sak_len;
    cfg.priority = priority;
    cfg.macsec_capability = MKA_CAP_INTEGRITY_CONF; /* int + conf, offset 0 */
    cfg.confidentiality_offset = MKA_CONF_OFFSET_0;
    cfg.macsec_desired = true;
    cfg.key_server_capable = key_server_capable ? true : false;
    cfg.role = MKA_ROLE_AUTO;
    cfg.send = mka_wolfmka_send;
    cfg.send_ctx = m;
    cfg.rng = m->rng;
    cfg.cmac = m->cmac;
    mka_wolfmka_secy_ops(&cfg.secy, m);
#ifdef WOLFIP_MKA_WOLFMKA_DEBUG
    mka_wolfmka_event_ops(&cfg.events, m);
#endif

    ret = (wm_Participant_Init(&m->p, &cfg) == MKA_OK) ? 0 : -1;
    /* cfg carries a plaintext copy of the CAK; wm_Participant_Init has taken
     * its own copy by now, so do not leave ours on the stack. */
    wpa_secure_zero(&cfg, sizeof(cfg));
    if (ret != 0) {
        mka_wolfmka_free(m);
    }
    return ret;
}

int mka_wolfmka_set_replay(struct mka_wolfmka *m, uint8_t replay_protect,
                           uint32_t window)
{
    if (m == NULL) {
        return -1;
    }
    m->replay_protect = replay_protect ? 1U : 0U;
    m->replay_window  = window;
    return 0;
}

int mka_wolfmka_init_eap(struct mka_wolfmka *m,
                         mka_wolfmka_send_fn send, void *send_ctx,
                         const uint8_t *msk, size_t msk_len, size_t cak_len,
                         const uint8_t *eap_session_id, size_t session_id_len,
                         const uint8_t peer_mac[6], const uint8_t auth_mac[6],
                         const uint8_t sci[8], uint8_t priority,
                         uint8_t key_server_capable,
                         struct macsec_tx_sc *tx, struct macsec_rx_sc *rx)
{
    uint8_t cak[MACSEC_KEY_LEN_MAX];
    uint8_t ckn[MACSEC_KEY_LEN_MAX];
    int     ret;

    if (msk == NULL || eap_session_id == NULL) {
        return -1;
    }
    if (cak_len != MACSEC_KEY_LEN_128 && cak_len != MACSEC_KEY_LEN_256) {
        return -1;
    }
    if (macsec_derive_cak(msk, msk_len, cak_len, peer_mac, auth_mac, cak) != 0) {
        return -1;
    }
    if (macsec_derive_ckn(msk, msk_len, eap_session_id, session_id_len,
                          peer_mac, auth_mac, ckn, cak_len) != 0) {
        wpa_secure_zero(cak, sizeof(cak));
        return -1;
    }
    ret = mka_wolfmka_init_psk(m, send, send_ctx, cak, cak_len, ckn, cak_len,
                               sci, priority, key_server_capable, cak_len,
                               tx, rx);
    wpa_secure_zero(cak, sizeof(cak));
    wpa_secure_zero(ckn, sizeof(ckn));
    return ret;
}

int mka_wolfmka_rx(struct mka_wolfmka *m, const uint8_t *frame, size_t len,
                   uint32_t now_ms)
{
    if (m == NULL || frame == NULL || len <= MKA_L2_HDR_LEN) {
        return -1;
    }
    /* Strip the L2 header: wolfMKA parses from the EAPOL PDU. */
    return (wm_Participant_Receive(&m->p, frame + MKA_L2_HDR_LEN,
                                   len - MKA_L2_HDR_LEN, now_ms) == MKA_OK)
               ? 0 : -1;
}

int mka_wolfmka_tick(struct mka_wolfmka *m, uint32_t now_ms)
{
    bool sent = false;
    if (m == NULL) {
        return -1;
    }
    return (wm_Participant_Run(&m->p, now_ms, &sent) == MKA_OK) ? 0 : -1;
}

int mka_wolfmka_installed(const struct mka_wolfmka *m)
{
    return (m != NULL && m->installed) ? 1 : 0;
}

void mka_wolfmka_free(struct mka_wolfmka *m)
{
    if (m == NULL) {
        return;
    }
    wm_Participant_Free(&m->p);
    if (m->cmac != NULL) {
        wm_Crypto_CmacFree(m->cmac);
    }
    if (m->rng != NULL) {
        wm_Crypto_RandomFree(m->rng);
    }
    /* Zeroise the wrapper: it holds no key material of its own, but scrubbing
     * clears the participant state and the tx/rx SC pointers so nothing stale
     * is reused after teardown. */
    wpa_secure_zero(m, sizeof(*m));
}
