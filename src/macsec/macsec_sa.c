/* macsec_sa.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include "macsec_sa.h"
#include "supplicant_features.h"
#include "wpa_crypto.h"          /* wpa_secure_zero */

#include <string.h>

#include <wolfssl/wolfcrypt/error-crypt.h>

static int macsec_sa_key_ok(size_t sak_len)
{
    return (sak_len == MACSEC_KEY_LEN_128 || sak_len == MACSEC_KEY_LEN_256);
}

/* Find the transmit SA holding an, or NULL. */
static struct macsec_tx_sa *macsec_tx_sa_find(struct macsec_tx_sc *sc,
                                              uint8_t an)
{
    size_t i;

    for (i = 0; i < (size_t)MACSEC_SA_PER_SC; i++) {
        if (sc->sa[i].in_use && sc->sa[i].an == an) {
            return &sc->sa[i];
        }
    }
    return NULL;
}

/* Find the receive SA holding an, or NULL. */
static struct macsec_rx_sa *macsec_rx_sa_find(struct macsec_rx_sc *sc,
                                              uint8_t an)
{
    size_t i;

    for (i = 0; i < (size_t)MACSEC_SA_PER_SC; i++) {
        if (sc->sa[i].in_use && sc->sa[i].an == an) {
            return &sc->sa[i];
        }
    }
    return NULL;
}

/* The slot an install should use: the one already holding an (a re-install of
 * the same Association Number replaces it), else a free one, else NULL. */
static struct macsec_tx_sa *macsec_tx_sa_slot(struct macsec_tx_sc *sc,
                                              uint8_t an)
{
    struct macsec_tx_sa *sa;
    size_t i;

    sa = macsec_tx_sa_find(sc, an);
    if (sa != NULL) {
        return sa;
    }
    for (i = 0; i < (size_t)MACSEC_SA_PER_SC; i++) {
        if (!sc->sa[i].in_use) {
            return &sc->sa[i];
        }
    }
    return NULL;
}

static struct macsec_rx_sa *macsec_rx_sa_slot(struct macsec_rx_sc *sc,
                                              uint8_t an)
{
    struct macsec_rx_sa *sa;
    size_t i;

    sa = macsec_rx_sa_find(sc, an);
    if (sa != NULL) {
        return sa;
    }
    for (i = 0; i < (size_t)MACSEC_SA_PER_SC; i++) {
        if (!sc->sa[i].in_use) {
            return &sc->sa[i];
        }
    }
    return NULL;
}

/* 1 while any SA remains installed on the channel. */
static uint8_t macsec_tx_sc_populated(const struct macsec_tx_sc *sc)
{
    size_t i;

    for (i = 0; i < (size_t)MACSEC_SA_PER_SC; i++) {
        if (sc->sa[i].in_use) {
            return 1U;
        }
    }
    return 0U;
}

static uint8_t macsec_rx_sc_populated(const struct macsec_rx_sc *sc)
{
    size_t i;

    for (i = 0; i < (size_t)MACSEC_SA_PER_SC; i++) {
        if (sc->sa[i].in_use) {
            return 1U;
        }
    }
    return 0U;
}

void macsec_tx_sc_init(struct macsec_tx_sc *sc)
{
    if (sc != NULL) {
        memset(sc, 0, sizeof(*sc));
    }
}

void macsec_rx_sc_init(struct macsec_rx_sc *sc)
{
    if (sc != NULL) {
        memset(sc, 0, sizeof(*sc));
    }
}

int macsec_tx_sc_set_key(struct macsec_tx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t encrypt, size_t conf_offset,
                         uint8_t include_sci, uint32_t initial_pn)
{
    struct macsec_tx_sa *sa;

    if (sc == NULL || sak == NULL || sci == NULL || !macsec_sa_key_ok(sak_len)) {
        return MACSEC_RX_BAD_ARG;
    }
    if (an > MACSEC_AN_MASK || initial_pn == 0
        || (conf_offset != 0 && conf_offset != 30 && conf_offset != 50)) {
        return MACSEC_RX_BAD_ARG;
    }
    sa = macsec_tx_sa_slot(sc, an);
    if (sa == NULL) {
        /* More keys live at once than the channel can hold. MKA never keeps
         * more than two, so this is a programming error rather than a
         * transient condition - refuse instead of evicting a live SA. */
        return MACSEC_RX_BAD_ARG;
    }

    /* The slot may hold a retired key; scrub before overwriting. */
    wpa_secure_zero(sa->sak, sizeof(sa->sak));
    memcpy(sa->sak, sak, sak_len);
    sa->sak_len = sak_len;
    sa->next_pn = initial_pn;
    sa->an      = an;
    sa->in_use  = 1U;

    /* Channel-wide settings come from the first install and are refreshed on
     * every one: MKA applies the negotiated cipher suite to the whole SC. */
    memcpy(sc->sci, sci, MACSEC_SCI_LEN);
    sc->conf_offset = conf_offset;
    sc->encrypt     = encrypt ? 1U : 0U;
    sc->include_sci = include_sci ? 1U : 0U;
    sc->in_use      = 1U;

    /* A rekey must not steal the wire from the key still in force: only take
     * the active AN when nothing else holds it. MKA moves it explicitly with
     * macsec_tx_sc_set_active() once every live peer reports receiving on the
     * new key. */
    if (!sc->active) {
        sc->active_an = an;
        sc->active    = 1U;
    }
    return 0;
}

int macsec_rx_sc_set_key(struct macsec_rx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t peer_sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t replay_protect, uint32_t replay_window,
                         size_t conf_offset)
{
    struct macsec_rx_sa *sa;

    if (sc == NULL || sak == NULL || peer_sci == NULL
        || !macsec_sa_key_ok(sak_len)) {
        return MACSEC_RX_BAD_ARG;
    }
    if (an > MACSEC_AN_MASK
        || (conf_offset != 0 && conf_offset != 30 && conf_offset != 50)) {
        return MACSEC_RX_BAD_ARG;
    }
    sa = macsec_rx_sa_slot(sc, an);
    if (sa == NULL) {
        return MACSEC_RX_BAD_ARG;
    }

    wpa_secure_zero(sa->sak, sizeof(sa->sak));
    memcpy(sa->sak, sak, sak_len);
    sa->sak_len   = sak_len;
    sa->lowest_pn = 1U;                 /* PN 0 is invalid */
    sa->an        = an;
    sa->in_use    = 1U;
    sa->enabled   = 1U;

    memcpy(sc->sci, peer_sci, MACSEC_SCI_LEN);
    sc->replay_window  = replay_window;
    sc->conf_offset    = conf_offset;
    sc->replay_protect = replay_protect ? 1U : 0U;
    sc->in_use         = 1U;
    return 0;
}

int macsec_tx_sc_delete_sa(struct macsec_tx_sc *sc, uint8_t an)
{
    struct macsec_tx_sa *sa;

    if (sc == NULL) {
        return MACSEC_RX_BAD_ARG;
    }
    sa = macsec_tx_sa_find(sc, an);
    if (sa == NULL) {
        return MACSEC_RX_NO_SA;
    }
    wpa_secure_zero(sa, sizeof(*sa));
    if (sc->active && sc->active_an == an) {
        sc->active = 0U;
    }
    sc->in_use = macsec_tx_sc_populated(sc);
    return 0;
}

int macsec_rx_sc_delete_sa(struct macsec_rx_sc *sc, uint8_t an)
{
    struct macsec_rx_sa *sa;

    if (sc == NULL) {
        return MACSEC_RX_BAD_ARG;
    }
    sa = macsec_rx_sa_find(sc, an);
    if (sa == NULL) {
        return MACSEC_RX_NO_SA;
    }
    wpa_secure_zero(sa, sizeof(*sa));
    sc->in_use = macsec_rx_sc_populated(sc);
    return 0;
}

int macsec_tx_sc_set_active(struct macsec_tx_sc *sc, uint8_t an,
                            uint8_t enable)
{
    if (sc == NULL) {
        return MACSEC_RX_BAD_ARG;
    }
    if (macsec_tx_sa_find(sc, an) == NULL) {
        return MACSEC_RX_NO_SA;
    }
    if (enable) {
        sc->active_an = an;
        sc->active    = 1U;
    }
    else if (sc->active && sc->active_an == an) {
        sc->active = 0U;
    }
    return 0;
}

int macsec_rx_sc_enable_sa(struct macsec_rx_sc *sc, uint8_t an,
                           uint8_t enable)
{
    struct macsec_rx_sa *sa;

    if (sc == NULL) {
        return MACSEC_RX_BAD_ARG;
    }
    sa = macsec_rx_sa_find(sc, an);
    if (sa == NULL) {
        return MACSEC_RX_NO_SA;
    }
    sa->enabled = enable ? 1U : 0U;
    return 0;
}

int macsec_tx_sc_next_pn(const struct macsec_tx_sc *sc, uint8_t an,
                         uint32_t *next_pn)
{
    size_t i;

    if (sc == NULL || next_pn == NULL) {
        return MACSEC_RX_BAD_ARG;
    }
    for (i = 0; i < (size_t)MACSEC_SA_PER_SC; i++) {
        if (sc->sa[i].in_use && sc->sa[i].an == an) {
            *next_pn = sc->sa[i].next_pn;
            return 0;
        }
    }
    return MACSEC_RX_NO_SA;
}

int macsec_rx_sc_set_lowest_pn(struct macsec_rx_sc *sc, uint8_t an,
                               uint32_t lowest_pn)
{
    struct macsec_rx_sa *sa;

    if (sc == NULL) {
        return MACSEC_RX_BAD_ARG;
    }
    sa = macsec_rx_sa_find(sc, an);
    if (sa == NULL) {
        return MACSEC_RX_NO_SA;
    }
    /* Delay protection only ever raises the bound; a peer advertising a lower
     * value must not be able to reopen an already-closed window. */
    if (lowest_pn > sa->lowest_pn) {
        sa->lowest_pn = lowest_pn;
    }
    return 0;
}

void macsec_tx_sc_free(struct macsec_tx_sc *sc)
{
    if (sc != NULL) {
        wpa_secure_zero(sc, sizeof(*sc));
    }
}

void macsec_rx_sc_free(struct macsec_rx_sc *sc)
{
    if (sc != NULL) {
        wpa_secure_zero(sc, sizeof(*sc));
    }
}

int macsec_tx(struct macsec_tx_sc *sc,
              const uint8_t da[MACSEC_MAC_LEN],
              const uint8_t sa[MACSEC_MAC_LEN],
              const uint8_t *payload, size_t payload_len,
              uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct macsec_protect_params p;
    struct macsec_tx_sa         *tsa;
    int ret;

    if (sc == NULL || !sc->in_use || !sc->active) {
        return MACSEC_RX_NO_SA;
    }
    tsa = macsec_tx_sa_find(sc, sc->active_an);
    if (tsa == NULL) {
        return MACSEC_RX_NO_SA;
    }
    /* PN exhausted: next_pn is parked at 0 once the ceiling has been used
     * (see below); a fresh SAK is required before it can wrap (802.1AE). */
    if (tsa->next_pn == 0U) {
        return MACSEC_RX_BAD_ARG;
    }

    memset(&p, 0, sizeof(p));
    p.da          = da;
    p.sa          = sa;
    p.sci         = sc->sci;
    p.sak         = tsa->sak;
    p.sak_len     = tsa->sak_len;
    p.conf_offset = sc->conf_offset;
    p.pn          = tsa->next_pn;
    p.an          = tsa->an;
    p.encrypt     = sc->encrypt;
    p.include_sci = sc->include_sci;

    ret = macsec_protect(&p, payload, payload_len, out, out_cap, out_len);
    if (ret != 0) {
        return ret;
    }
    /* Advance only after a successful protect; stop at the ceiling so the
     * next call reports exhaustion rather than wrapping to 0. */
    if (tsa->next_pn == MACSEC_PN_MAX) {
        tsa->next_pn = 0U;             /* mark exhausted */
    }
    else {
        tsa->next_pn++;
    }
    return 0;
}

int macsec_rx(struct macsec_rx_sc *sc,
              const uint8_t *frame, size_t frame_len,
              uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct macsec_validate_params vp;
    struct macsec_sectag          tag;
    struct macsec_rx_sa          *rsa;
    int ret;

    if (sc == NULL || !sc->in_use || frame == NULL || out == NULL
        || out_len == NULL) {
        return MACSEC_RX_BAD_ARG;
    }
    if (frame_len < MACSEC_ETH_ADDR_PAIR_LEN + MACSEC_SECTAG_MIN_LEN
                    + MACSEC_ICV_LEN) {
        return MACSEC_RX_BAD_ARG;
    }

    /* Demultiplex before doing any crypto: parse the SecTAG, then pick the
     * Secure Association it names. */
    if (macsec_sectag_parse(frame + MACSEC_ETH_ADDR_PAIR_LEN,
                            frame_len - MACSEC_ETH_ADDR_PAIR_LEN, &tag) != 0) {
        return MACSEC_RX_BAD_ARG;
    }
    /* A frame carrying an in-band SCI belongs to the Secure Channel that SCI
     * names (802.1AE 10.6). Without this check every member of a
     * Connectivity Association - all holding the same SAK - would land on
     * this channel and share one replay window, so the member with the lower
     * packet numbers would be discarded as a replay. */
    if (tag.sci_present
        && memcmp(tag.sci, sc->sci, MACSEC_SCI_LEN) != 0) {
        return MACSEC_RX_NO_SA;
    }
    rsa = macsec_rx_sa_find(sc, (uint8_t)(tag.tci_an & MACSEC_AN_MASK));
    if (rsa == NULL || !rsa->enabled) {
        return MACSEC_RX_NO_SA;
    }

    memset(&vp, 0, sizeof(vp));
    vp.sak         = rsa->sak;
    vp.sak_len     = rsa->sak_len;
    vp.sci         = sc->sci;
    vp.conf_offset = sc->conf_offset;

    /* Authenticate first: the replay window must only ever be tested and
     * advanced on an authenticated PN, so a forged PN cannot move it. */
    ret = macsec_validate(&vp, frame, frame_len, out, out_cap, out_len, &tag);
    if (ret != 0) {
        /* Keep a forgery distinct from a parse error and from a crypto
         * backend failure: an MKA-driven stack counts an authentication
         * failure against the peer (InPktsNotValid) and may tear the CA
         * down, which a transient wolfCrypt error must not trigger. */
        if (ret == MACSEC_ICV_FAIL) {
            return MACSEC_RX_AUTH_FAIL;
        }
        if (ret == BAD_FUNC_ARG) {
            return MACSEC_RX_BAD_ARG;
        }
        return MACSEC_RX_CRYPTO_ERR;
    }
    if (sc->replay_protect && tag.pn < rsa->lowest_pn) {
        wpa_secure_zero(out, *out_len);
        *out_len = 0;
        return MACSEC_RX_REPLAY;
    }

    /* Advance this SA's window: lowest acceptable PN becomes pn + 1 - window,
     * floored at 1, and never moves backwards. Per-SA because the two keys
     * live across a rekey carry independent PN sequences. */
    if (sc->replay_protect) {
        uint32_t new_low;
        if (tag.pn >= sc->replay_window) {
            new_low = tag.pn - sc->replay_window + 1U;
        }
        else {
            new_low = 1U;
        }
        if (new_low > rsa->lowest_pn) {
            rsa->lowest_pn = new_low;
        }
    }
    return MACSEC_RX_OK;
}
