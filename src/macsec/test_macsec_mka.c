/* test_macsec_mka.c
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

/* The wolfMKA adapter against the software SecY, driven through the
 * MkaSecyOps table the participant was built with. This exercises the
 * callback sequence wolfMKA itself runs at a rekey - install the new key,
 * hand transmit over, retire the old key - without needing a peer, a wire or
 * a converged Connectivity Association. The retire step is the regression
 * this file exists for: it must leave the key that is carrying traffic
 * alone. */

#include "supplicant_features.h"     /* load wolfSSL config before wolfcrypt */
#include "mka_wolfmka.h"
#include "macsec_test.h"

static const uint8_t CAK[16] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
static const uint8_t CKN[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t OUR_SCI[8]  = { 0x02,0,0,0,0,0xaa,0x00,0x01 };
static const uint8_t PEER_SCI[8] = { 0x02,0,0,0,0,0xbb,0x00,0x01 };
static const uint8_t DA[6]       = { 0x02,0,0,0,0,0xbb };
static const uint8_t SA[6]       = { 0x02,0,0,0,0,0xaa };
static const uint8_t SAK_A[16] = {
    0xad,0x7a,0x2b,0xd0,0x3e,0xac,0x83,0x5a,
    0x6f,0x62,0x0f,0xdc,0xb5,0x06,0xb3,0x45
};
static const uint8_t SAK_B[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
};
static const uint8_t SAK_256[32] = {
    0xe3,0xc0,0x8a,0x8f,0x06,0xc6,0xe3,0xad,
    0x95,0xa7,0x05,0x57,0xb2,0x3f,0x75,0x48,
    0x3c,0xe3,0x30,0x21,0xa9,0xc7,0x2b,0x70,
    0x25,0x66,0x62,0x04,0xc6,0x9c,0x0b,0x72
};

/* The participant needs a transmit callback; the wire is not under test. */
static int sink_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx; (void)frame; (void)len;
    return 0;
}

/* Can the transmit channel still protect a frame? */
static int tx_works(struct macsec_tx_sc *tx)
{
    uint8_t payload[48];
    uint8_t frame[256];
    size_t  flen = 0;

    fill_payload(payload, sizeof(payload), 0x11);
    return macsec_tx(tx, DA, SA, payload, sizeof(payload), frame,
                     sizeof(frame), &flen) == 0;
}

static int test_init_validation(void)
{
    struct mka_wolfmka  m;
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    int fails = 0;

    printf("Test 1: init argument validation\n");
    /* A CAK is 128 or 256 bits; a truncated one must not reach the key
     * derivation with a partly uninitialised buffer behind it. */
    fails += expect_true(mka_wolfmka_init_psk(&m, sink_send, NULL, CAK, 8,
                         CKN, sizeof(CKN), OUR_SCI, 20, 1, 16, &tx, &rx) != 0,
                         "8-octet CAK rejected");
    fails += expect_true(mka_wolfmka_init_psk(&m, sink_send, NULL, CAK, 12,
                         CKN, sizeof(CKN), OUR_SCI, 20, 1, 16, &tx, &rx) != 0,
                         "12-octet CAK rejected");
    fails += expect_true(mka_wolfmka_init_psk(&m, sink_send, NULL, CAK, 0,
                         CKN, sizeof(CKN), OUR_SCI, 20, 1, 16, &tx, &rx) != 0,
                         "zero-length CAK rejected");
    fails += expect_true(mka_wolfmka_init_psk(&m, sink_send, NULL, CAK,
                         sizeof(CAK), CKN, 0, OUR_SCI, 20, 1, 16, &tx, &rx)
                         != 0, "zero-length CKN rejected");
    fails += expect_true(mka_wolfmka_init_psk(&m, sink_send, NULL, CAK,
                         sizeof(CAK), CKN, sizeof(CKN), OUR_SCI, 20, 1, 24,
                         &tx, &rx) != 0, "24-octet SAK length rejected");

    fails += expect_true(mka_wolfmka_init_psk(&m, sink_send, NULL, CAK,
                         sizeof(CAK), CKN, sizeof(CKN), OUR_SCI, 20, 1, 16,
                         &tx, &rx) == 0, "valid PSK participant initialised");
    mka_wolfmka_free(&m);
    return fails;
}

/* The callback sequence wolfMKA runs at a rekey, in order. */
static int test_rekey_and_retire(void)
{
    struct mka_wolfmka   m;
    struct macsec_tx_sc  tx;
    struct macsec_rx_sc  rx;
    const MkaSecyOps    *ops;
    void                *ctx;
    int fails = 0;

    printf("Test 2: rekey, transmit handover, retire\n");
    if (mka_wolfmka_init_psk(&m, sink_send, NULL, CAK, sizeof(CAK), CKN,
                             sizeof(CKN), OUR_SCI, 20, 1, 16, &tx, &rx) != 0) {
        printf("  [FAIL] participant init\n");
        return 1;
    }
    ops = &m.p.cfg.secy;
    ctx = ops->ctx;

    fails += expect_true(ops->set_cipher_suite(ctx, OUR_SCI,
                         MKA_CIPHER_GCM_AES_128, 0, MKA_CONF_OFFSET_0) == 0,
                         "GCM-AES-128 cipher suite accepted");

    /* First key, AN 0. Installing it does not by itself mean the link is
     * protected - wolfMKA holds transmit back until every live peer reports
     * receiving on the key. */
    fails += expect_true(ops->install_tx_sa(ctx, OUR_SCI, 0, 1, SAK_A, 16)
                         == 0, "transmit SA installed under AN 0");
    fails += expect_true(mka_wolfmka_installed(&m) == 0,
                         "not reported installed before transmit is enabled");
    fails += expect_true(ops->install_rx_sa(ctx, PEER_SCI, 0, 1, SAK_A, 16)
                         == 0, "receive SA installed under AN 0");
    fails += expect_true(ops->enable_transmit(ctx, 0, true) == 0,
                         "transmit enabled on AN 0");
    fails += expect_true(mka_wolfmka_installed(&m) == 1,
                         "reported installed once transmit is enabled");
    fails += expect_true(tx_works(&tx), "frames are protected on AN 0");

    /* A SAK whose length disagrees with the negotiated suite is a silent
     * downgrade; refuse it. */
    fails += expect_true(ops->install_tx_sa(ctx, OUR_SCI, 2, 9, SAK_256, 32)
                         != 0, "SAK of the wrong length for the suite refused");

    /* Rekey: second key under AN 1, make-before-break. */
    fails += expect_true(ops->install_tx_sa(ctx, OUR_SCI, 1, 2, SAK_B, 16)
                         == 0, "transmit SA installed under AN 1");
    fails += expect_true(ops->install_rx_sa(ctx, PEER_SCI, 1, 2, SAK_B, 16)
                         == 0, "receive SA installed under AN 1");
    fails += expect_true(tx.active_an == 0,
                         "still transmitting on AN 0 until the handover");
    fails += expect_true(ops->enable_transmit(ctx, 1, true) == 0,
                         "transmit handed over to AN 1");
    fails += expect_true(ops->enable_transmit(ctx, 0, false) == 0,
                         "AN 0 taken off the wire");
    fails += expect_true(mka_wolfmka_installed(&m) == 1,
                         "still installed across the handover");

    /* Retire the old key. wolfMKA deletes the transmit SA first (sci NULL),
     * then each peer's receive SA. Neither may disturb AN 1. */
    fails += expect_true(ops->delete_sa(ctx, NULL, 0) == 0,
                         "old transmit SA deleted");
    fails += expect_true(ops->delete_sa(ctx, PEER_SCI, 0) == 0,
                         "old receive SA deleted");
    fails += expect_true(mka_wolfmka_installed(&m) == 1,
                         "still installed after the old key is retired");
    fails += expect_true(tx_works(&tx),
                         "frames are still protected after the retire");

    /* Teardown deletes the key in force; the flag must follow. */
    fails += expect_true(ops->delete_sa(ctx, NULL, 1) == 0,
                         "current transmit SA deleted");
    fails += expect_true(mka_wolfmka_installed(&m) == 0,
                         "no longer reported installed after teardown");
    fails += expect_true(!tx_works(&tx), "transmit refused after teardown");
    fails += expect_true(ops->delete_sa(ctx, PEER_SCI, 1) == 0,
                         "current receive SA deleted");

    mka_wolfmka_free(&m);
    return fails;
}

/* The replay policy is a managed object, not a literal. */
static int test_replay_policy(void)
{
    struct mka_wolfmka   m;
    struct macsec_tx_sc  tx;
    struct macsec_rx_sc  rx;
    const MkaSecyOps    *ops;
    int fails = 0;

    printf("Test 3: configurable replay window\n");
    if (mka_wolfmka_init_psk(&m, sink_send, NULL, CAK, sizeof(CAK), CKN,
                             sizeof(CKN), OUR_SCI, 20, 1, 16, &tx, &rx) != 0) {
        printf("  [FAIL] participant init\n");
        return 1;
    }
    ops = &m.p.cfg.secy;
    fails += expect_true(mka_wolfmka_set_replay(&m, 1, 32) == 0,
                         "replay window widened");
    fails += expect_true(ops->install_rx_sa(ops->ctx, PEER_SCI, 0, 1, SAK_A,
                         16) == 0, "receive SA installed");
    fails += expect_true(rx.replay_protect == 1 && rx.replay_window == 32,
                         "the configured window reached the Secure Channel");

    /* Delay protection raises the window's lower bound, and only ever
     * upwards. */
    fails += expect_true(ops->set_lowest_pn(ops->ctx, PEER_SCI, 0, 100) == 0,
                         "lowest PN raised");
    fails += expect_true(ops->set_lowest_pn(ops->ctx, PEER_SCI, 0, 50) == 0,
                         "a lower value is accepted but ignored");
    fails += expect_true(rx.sa[0].lowest_pn == 100,
                         "the bound never moves backwards");
    /* This data plane is 32-bit PN only; an XPN-sized value must be refused
     * rather than truncated into a window that would accept too much. */
    fails += expect_true(ops->set_lowest_pn(ops->ctx, PEER_SCI, 0,
                         (uint64_t)MACSEC_PN_MAX + 1U) != 0,
                         "a packet number beyond 32 bits is refused");
    mka_wolfmka_free(&m);
    return fails;
}

int main(void)
{
    int fails = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    fails += test_init_validation();
    fails += test_rekey_and_retire();
    fails += test_replay_policy();

    printf("\n%s: macsec_mka (%d failure%s)\n",
           fails == 0 ? "PASS" : "FAIL", fails, fails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}
