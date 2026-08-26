/* macsec_sa.h
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

/* Stateful 802.1AE Secure Association layer. Wraps the stateless SecY
 * transform (macsec_secy.c) with the per-SA packet-number counter (transmit)
 * and the replay window (receive) that a real SecY maintains. This is the
 * seam the wolfIP datapath drives: outbound frames go through macsec_tx()
 * before ll->send, inbound MACsec frames (EtherType 0x88E5) through
 * macsec_rx() after the link-layer demux. SAKs are installed here by the MKA
 * control plane (see mka_wolfmka.h).
 *
 * A Secure Channel holds several Secure Associations, one per Association
 * Number, because MKA rekeys make-before-break: the Key Server distributes a
 * new SAK under a fresh AN while the previous one is still carrying traffic,
 * and only retires the old SA once every live peer has moved over. A channel
 * with a single SA would lose the live key the moment the old one is retired,
 * and could not validate a lagging peer's frames during the handover.
 */

#ifndef WOLFIP_MACSEC_SA_H
#define WOLFIP_MACSEC_SA_H

#include <stdint.h>
#include <stddef.h>

#include "macsec_secy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for macsec_rx() / macsec_tx(). */
#define MACSEC_RX_OK            0
#define MACSEC_RX_AUTH_FAIL   (-1)   /* ICV / GCM authentication failed     */
#define MACSEC_RX_REPLAY      (-2)   /* PN below the replay window          */
#define MACSEC_RX_BAD_ARG     (-3)   /* bad argument or malformed frame     */
#define MACSEC_RX_NO_SA       (-4)   /* no SA for this frame's SCI / AN     */
#define MACSEC_RX_CRYPTO_ERR  (-5)   /* crypto backend failure, not forgery */

/* PN exhaustion: 0xFFFFFFFF is the last usable 32-bit packet number; a fresh
 * SAK must be installed before it wraps (XPN is out of scope). */
#define MACSEC_PN_MAX         0xFFFFFFFFUL

/* Secure Associations held per Secure Channel. MKA keeps two keys live at a
 * time (Latest and Old), which is the default here; 802.1AE allows up to four
 * since the AN is a two-bit field. Override at build time for a data plane
 * that must hold more. */
#ifndef MACSEC_SA_PER_SC
#define MACSEC_SA_PER_SC          2U
#endif
#if MACSEC_SA_PER_SC < 1U || MACSEC_SA_PER_SC > 4U
#error "MACSEC_SA_PER_SC must be 1..4: the Association Number is two bits wide"
#endif

/* One transmit Secure Association: a SAK under one Association Number, with
 * its own packet-number counter. */
struct macsec_tx_sa {
    uint8_t  sak[MACSEC_KEY_LEN_MAX];
    size_t   sak_len;                  /* 16 or 32; 0 = slot free            */
    uint32_t next_pn;                  /* next packet number to transmit     */
    uint8_t  an;                       /* Association Number                 */
    uint8_t  in_use;
};

/* One receive Secure Association: a SAK under one Association Number, with
 * its own replay window. Per-SA rather than per-SC because two keys are live
 * across a rekey and each carries an independent PN sequence. */
struct macsec_rx_sa {
    uint8_t  sak[MACSEC_KEY_LEN_MAX];
    size_t   sak_len;
    uint32_t lowest_pn;                /* replay window lower bound          */
    uint8_t  an;
    uint8_t  in_use;
    uint8_t  enabled;                  /* cleared by macsec_rx_sc_enable_sa  */
};

/* Transmit Secure Channel: our SCI and the SAs installed under it. Only the
 * SA named by active_an protects outbound frames; the others stay installed
 * so a peer that has not yet moved to the new key can still be answered. */
struct macsec_tx_sc {
    struct macsec_tx_sa sa[MACSEC_SA_PER_SC];
    size_t   conf_offset;              /* 0/30/50                            */
    uint8_t  sci[MACSEC_SCI_LEN];      /* our SCI                            */
    uint8_t  active_an;                /* AN currently protecting traffic    */
    uint8_t  active;                   /* 1 when active_an names a live SA   */
    uint8_t  encrypt;                  /* 1 = confidentiality, 0 = integrity */
    uint8_t  include_sci;              /* set SC bit / include SCI in SecTAG */
    uint8_t  in_use;                   /* at least one SA installed          */
};

/* Receive Secure Channel: one peer's SCI and the SAs installed under it. A
 * frame is accepted only when its SecTAG SCI names this channel, so every
 * member of a Connectivity Association gets its own channel and its own
 * replay state rather than sharing one. */
struct macsec_rx_sc {
    struct macsec_rx_sa sa[MACSEC_SA_PER_SC];
    size_t   conf_offset;
    uint32_t replay_window;            /* frames of reorder tolerated        */
    uint8_t  sci[MACSEC_SCI_LEN];      /* peer SCI                           */
    uint8_t  replay_protect;
    uint8_t  in_use;                   /* at least one SA installed          */
};

/* Ready a Secure Channel for use. A channel must be initialised (or be
 * zero-initialised storage) before its first macsec_*_sc_set_key(), since
 * installing a key inspects the channel's existing Secure Associations to
 * pick a slot. */
void macsec_tx_sc_init(struct macsec_tx_sc *sc);
void macsec_rx_sc_init(struct macsec_rx_sc *sc);

/* Install a SAK on the transmit SC under Association Number an. initial_pn is
 * normally 1 (PN 0 is invalid). encrypt selects confidentiality vs
 * integrity-only; conf_offset is 0/30/50. The first SA installed also becomes
 * the active one; a later install does not steal the active AN, so a rekey
 * keeps transmitting on the old key until macsec_tx_sc_set_active() moves it.
 * Returns 0 on success, MACSEC_RX_BAD_ARG on a bad argument or a full channel
 * (more than MACSEC_SA_PER_SC keys live at once). */
int macsec_tx_sc_set_key(struct macsec_tx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t encrypt, size_t conf_offset,
                         uint8_t include_sci, uint32_t initial_pn);

/* Install a SAK on the receive SC under Association Number an.
 * replay_protect enables the window; replay_window is the number of
 * out-of-order frames tolerated below the highest accepted PN. Note the
 * window is a sliding low-water mark, not a bitmap: a duplicate inside a
 * non-zero window is accepted, which 802.1AE permits. Returns 0 on success,
 * MACSEC_RX_BAD_ARG on a bad argument or a full channel. */
int macsec_rx_sc_set_key(struct macsec_rx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t peer_sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t replay_protect, uint32_t replay_window,
                         size_t conf_offset);

/* Tear down one Secure Association, scrubbing its key. Only the SA under an
 * is touched: an MKA retire of the Old key must leave the Latest key
 * carrying traffic. Deleting the active transmit SA clears sc->active, so the
 * caller can see that the channel is no longer protecting. Returns 0 on
 * success, MACSEC_RX_NO_SA when no SA holds that AN. */
int macsec_tx_sc_delete_sa(struct macsec_tx_sc *sc, uint8_t an);
int macsec_rx_sc_delete_sa(struct macsec_rx_sc *sc, uint8_t an);

/* Select which installed transmit SA protects outbound frames (enable != 0),
 * or stop transmitting on it (enable == 0). Returns 0 on success,
 * MACSEC_RX_NO_SA when no SA holds that AN. */
int macsec_tx_sc_set_active(struct macsec_tx_sc *sc, uint8_t an,
                            uint8_t enable);

/* Enable or disable validation on one receive SA. Returns 0 on success,
 * MACSEC_RX_NO_SA when no SA holds that AN. */
int macsec_rx_sc_enable_sa(struct macsec_rx_sc *sc, uint8_t an,
                           uint8_t enable);

/* Read a transmit SA's next packet number (MKA advertises it as the Lowest
 * Acceptable PN). Returns 0 on success, MACSEC_RX_NO_SA when no SA holds that
 * AN. */
int macsec_tx_sc_next_pn(const struct macsec_tx_sc *sc, uint8_t an,
                         uint32_t *next_pn);

/* Raise a receive SA's replay-window lower bound to lowest_pn (delay
 * protection). Never moves the bound backwards. Returns 0 on success,
 * MACSEC_RX_NO_SA when no SA holds that AN. */
int macsec_rx_sc_set_lowest_pn(struct macsec_rx_sc *sc, uint8_t an,
                               uint32_t lowest_pn);

/* Scrub every SA on a channel and leave it inert. */
void macsec_tx_sc_free(struct macsec_tx_sc *sc);
void macsec_rx_sc_free(struct macsec_rx_sc *sc);

/* Protect payload (a user MSDU starting at its EtherType) into a MACsec frame
 * using the active SA's next PN, then advance that counter. Returns 0 on
 * success, MACSEC_RX_NO_SA when no SA is active, MACSEC_RX_BAD_ARG on PN
 * exhaustion (a rekey is needed) or a bad argument, or a negative wolfCrypt
 * error from the transform. */
int macsec_tx(struct macsec_tx_sc *sc,
              const uint8_t da[MACSEC_MAC_LEN],
              const uint8_t sa[MACSEC_MAC_LEN],
              const uint8_t *payload, size_t payload_len,
              uint8_t *out, size_t out_cap, size_t *out_len);

/* Validate a received MACsec frame against the SA its SecTAG names and
 * enforce that SA's replay window. On success the recovered MSDU is written
 * to out and *out_len set. Returns MACSEC_RX_OK, MACSEC_RX_AUTH_FAIL,
 * MACSEC_RX_REPLAY, MACSEC_RX_NO_SA, MACSEC_RX_CRYPTO_ERR or
 * MACSEC_RX_BAD_ARG. */
int macsec_rx(struct macsec_rx_sc *sc,
              const uint8_t *frame, size_t frame_len,
              uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_MACSEC_SA_H */
