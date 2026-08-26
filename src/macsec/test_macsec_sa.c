/* test_macsec_sa.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Stand-alone loopback test for src/macsec/macsec_sa.c (the stateful SecY SA
 * layer). A transmit SC and a receive SC share a SAK; frames are protected by
 * the TX SC and validated by the RX SC. Verifies:
 *   1. In-order delivery of a burst (PN increments, all accepted).
 *   2. Replay window: reorder within the window accepted, below-window
 *      rejected as replay.
 *   3. Strict mode (window 0): duplicates / old PNs rejected.
 *   4. Integrity-only loopback.
 *   5. Tamper -> authentication failure.
 *   6. PN exhaustion -> transmit refused (rekey needed).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "macsec_sa.h"
#include "macsec_test.h"

#define BURST      8
#define FRAME_CAP  256

static const uint8_t DA[6]  = { 0x02,0,0,0,0,0xbb };
static const uint8_t SA[6]  = { 0x02,0,0,0,0,0xaa };
static const uint8_t SCI[8] = { 0x02,0,0,0,0,0xaa,0x00,0x01 };
static const uint8_t SAK[16] = {
    0xad,0x7a,0x2b,0xd0,0x3e,0xac,0x83,0x5a,
    0x6f,0x62,0x0f,0xdc,0xb5,0x06,0xb3,0x45
};

/* Protect a burst of frames (PN 1..BURST) into frames[]/lens[]. */
static int make_burst(struct macsec_tx_sc *tx,
                      uint8_t frames[BURST][FRAME_CAP], size_t lens[BURST])
{
    uint8_t payload[48];
    int i;
    for (i = 0; i < BURST; i++) {
        fill_payload(payload, sizeof(payload), (uint8_t)i);
        if (macsec_tx(tx, DA, SA, payload, sizeof(payload),
                      frames[i], FRAME_CAP, &lens[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int test_in_order(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t frames[BURST][FRAME_CAP];
    size_t  lens[BURST];
    uint8_t rec[FRAME_CAP];
    size_t  rlen;
    uint32_t next_pn = 0;
    int     i, fails = 0, ok = 1;

    printf("Test 1: in-order burst loopback\n");
    macsec_tx_sc_init(&tx);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1 /*encrypt*/, 0, 1, 1);
    macsec_rx_sc_init(&rx);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1 /*replay*/, 4, 0);
    if (make_burst(&tx, frames, lens) != 0) {
        printf("  [FAIL] burst protect error\n"); return 1;
    }
    for (i = 0; i < BURST; i++) {
        if (macsec_rx(&rx, frames[i], lens[i], rec, sizeof(rec), &rlen)
            != MACSEC_RX_OK) {
            ok = 0;
        }
    }
    fails += expect_true(ok, "all in-order frames accepted");
    fails += expect_true(macsec_tx_sc_next_pn(&tx, 0, &next_pn) == 0
                         && next_pn == (uint32_t)(BURST + 1),
                         "TX PN advanced past the burst");
    return fails;
}

static int test_replay_window(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t frames[BURST][FRAME_CAP];
    size_t  lens[BURST];
    uint8_t rec[FRAME_CAP];
    size_t  rlen;
    int     fails = 0;

    printf("Test 2: replay window (reorder in, old out)\n");
    macsec_tx_sc_init(&tx);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_rx_sc_init(&rx);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1 /*replay*/, 4 /*window*/, 0);
    make_burst(&tx, frames, lens);   /* frames[i] carries PN i+1 */

    /* Accept PN 5 first (index 4). */
    fails += expect_true(
        macsec_rx(&rx, frames[4], lens[4], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "PN 5 accepted");
    /* PN 3 is within window (5-4+1=2 .. ) -> accepted. */
    fails += expect_true(
        macsec_rx(&rx, frames[2], lens[2], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "PN 3 within window accepted");
    /* PN 1 is below the window lower bound -> replay. */
    fails += expect_true(
        macsec_rx(&rx, frames[0], lens[0], rec, sizeof(rec), &rlen)
            == MACSEC_RX_REPLAY, "PN 1 below window rejected");
    return fails;
}

static int test_strict_mode(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t frames[BURST][FRAME_CAP];
    size_t  lens[BURST];
    uint8_t rec[FRAME_CAP];
    size_t  rlen;
    int     fails = 0;

    printf("Test 3: strict mode (window 0) duplicate rejection\n");
    macsec_tx_sc_init(&tx);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_rx_sc_init(&rx);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 0 /*window=0*/, 0);
    make_burst(&tx, frames, lens);

    fails += expect_true(
        macsec_rx(&rx, frames[2], lens[2], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "PN 3 accepted");
    fails += expect_true(
        macsec_rx(&rx, frames[2], lens[2], rec, sizeof(rec), &rlen)
            == MACSEC_RX_REPLAY, "duplicate PN 3 rejected");
    fails += expect_true(
        macsec_rx(&rx, frames[1], lens[1], rec, sizeof(rec), &rlen)
            == MACSEC_RX_REPLAY, "older PN 2 rejected");
    fails += expect_true(
        macsec_rx(&rx, frames[3], lens[3], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "newer PN 4 accepted");
    return fails;
}

static int test_integrity_only(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t payload[48];
    uint8_t frame[FRAME_CAP];
    uint8_t rec[FRAME_CAP];
    size_t  flen, rlen;
    int     fails = 0;

    printf("Test 4: integrity-only loopback\n");
    fill_payload(payload, sizeof(payload), 0x40);
    macsec_tx_sc_init(&tx);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 0 /*integrity*/, 0, 1, 1);
    macsec_rx_sc_init(&rx);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 4, 0);
    if (macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame,
                  sizeof(frame), &flen) != 0) {
        printf("  [FAIL] tx error\n"); return 1;
    }
    fails += expect_true(
        macsec_rx(&rx, frame, flen, rec, sizeof(rec), &rlen) == MACSEC_RX_OK
        && rlen == sizeof(payload)
        && memcmp(rec, payload, sizeof(payload)) == 0,
        "integrity-only frame recovered");
    return fails;
}

static int test_tamper(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t payload[48];
    uint8_t frame[FRAME_CAP];
    uint8_t rec[FRAME_CAP];
    size_t  flen, rlen;
    int     fails = 0;

    printf("Test 5: tamper -> auth fail\n");
    fill_payload(payload, sizeof(payload), 0x20);
    macsec_tx_sc_init(&tx);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_rx_sc_init(&rx);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 4, 0);
    macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame, sizeof(frame),
              &flen);
    frame[flen - 2] ^= 0x01;         /* corrupt the ICV */
    fails += expect_true(
        macsec_rx(&rx, frame, flen, rec, sizeof(rec), &rlen)
            == MACSEC_RX_AUTH_FAIL, "tampered frame -> AUTH_FAIL");
    return fails;
}

static int test_pn_exhaustion(void)
{
    struct macsec_tx_sc tx;
    uint8_t payload[48];
    uint8_t frame[FRAME_CAP];
    size_t  flen;
    int     fails = 0;

    printf("Test 6: PN exhaustion\n");
    fill_payload(payload, sizeof(payload), 0x10);
    macsec_tx_sc_init(&tx);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, MACSEC_PN_MAX);
    fails += expect_true(
        macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame,
                  sizeof(frame), &flen) == 0, "last PN transmitted");
    fails += expect_true(
        macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame,
                  sizeof(frame), &flen) == MACSEC_RX_BAD_ARG,
        "transmit refused after PN exhaustion");
    return fails;
}


/* A second SAK and a second peer SCI, for the rekey and demux tests. */
static const uint8_t SAK2[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
};
static const uint8_t SCI_B[8] = { 0x02,0,0,0,0,0xcc,0x00,0x01 };

/* Protect one frame on the transmit channel's active SA. */
static int protect_one(struct macsec_tx_sc *tx, uint8_t *frame, size_t *len)
{
    uint8_t payload[48];

    fill_payload(payload, sizeof(payload), 0x5a);
    return macsec_tx(tx, DA, SA, payload, sizeof(payload), frame, FRAME_CAP,
                     len);
}

/* MKA rekeys make-before-break: the Key Server distributes a new SAK under a
 * fresh Association Number while the old one is still carrying traffic, and
 * retires the old SA only once every live peer has moved over. A channel
 * holding a single SA would lose the live key at that retire - the data plane
 * would report itself installed while every transmit failed. */
static int test_two_key_window(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t old_frame[FRAME_CAP];
    uint8_t old_frame2[FRAME_CAP];
    uint8_t new_frame[FRAME_CAP];
    uint8_t rec[FRAME_CAP];
    size_t  old_len = 0, old_len2 = 0, new_len = 0, rlen = 0;
    int     fails = 0;

    printf("Test 7: make-before-break two-key window\n");
    macsec_tx_sc_init(&tx);
    macsec_rx_sc_init(&rx);

    /* Old key, AN 0: installed and carrying traffic. */
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 0, 0);
    fails += expect_true(protect_one(&tx, old_frame, &old_len) == 0,
                         "old key transmits");
    /* A second old-key frame, held back to stand in for a peer that is still
     * transmitting under the old SAK once we have moved on. */
    fails += expect_true(protect_one(&tx, old_frame2, &old_len2) == 0,
                         "second old-key frame built");

    /* Rekey: new key under AN 1. It must not steal the wire until the
     * control plane says so. */
    macsec_tx_sc_set_key(&tx, SAK2, 16, SCI, 1, 1, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK2, 16, SCI, 1, 1, 0, 0);
    fails += expect_true(tx.active_an == 0,
                         "install does not move transmit onto the new key");

    /* Both keys validate while the handover is in flight. */
    fails += expect_true(macsec_rx(&rx, old_frame, old_len, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_OK, "old-key frame validates");

    fails += expect_true(macsec_tx_sc_set_active(&tx, 1, 1) == 0,
                         "transmit moves to the new key");
    fails += expect_true(protect_one(&tx, new_frame, &new_len) == 0,
                         "new key transmits");
    fails += expect_true(macsec_rx(&rx, new_frame, new_len, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_OK, "new-key frame validates");
    /* A lagging peer still on the old key is still heard - this is the point
     * of make-before-break receive. */
    fails += expect_true(macsec_rx(&rx, old_frame2, old_len2, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_OK,
                         "lagging peer on the old key still validates");

    /* Retire the old key. The new one must survive untouched. */
    fails += expect_true(macsec_tx_sc_delete_sa(&tx, 0) == 0,
                         "old transmit SA deleted");
    fails += expect_true(macsec_rx_sc_delete_sa(&rx, 0) == 0,
                         "old receive SA deleted");
    fails += expect_true(tx.active && tx.active_an == 1,
                         "transmit still active on the new key after retire");
    fails += expect_true(protect_one(&tx, new_frame, &new_len) == 0,
                         "transmit survives the retire");
    fails += expect_true(macsec_rx(&rx, new_frame, new_len, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_OK,
                         "receive survives the retire");
    /* The retired key is gone, not merely disabled. */
    fails += expect_true(macsec_rx(&rx, old_frame, old_len, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_NO_SA,
                         "retired key no longer validates");

    /* Deleting the SA that was protecting leaves the channel unprotected. */
    fails += expect_true(macsec_tx_sc_delete_sa(&tx, 1) == 0,
                         "active transmit SA deleted");
    fails += expect_true(tx.active == 0, "channel reports it stopped protecting");
    fails += expect_true(protect_one(&tx, new_frame, &new_len)
                         == MACSEC_RX_NO_SA, "transmit refused with no SA");
    macsec_tx_sc_free(&tx);
    macsec_rx_sc_free(&rx);
    return fails;
}

/* Every member of a Connectivity Association holds the same SAK, so a frame
 * from peer B authenticates against peer C's channel just fine. Only the
 * SecTAG SCI tells them apart; without that check they share one replay
 * window and the member with the lower packet numbers is discarded. */
static int test_sci_demux(void)
{
    struct macsec_tx_sc tx_b;
    struct macsec_rx_sc rx_c;
    uint8_t frame[FRAME_CAP];
    uint8_t rec[FRAME_CAP];
    size_t  flen = 0, rlen = 0;
    int     fails = 0;

    printf("Test 8: SecTAG SCI and AN demultiplexing\n");
    macsec_tx_sc_init(&tx_b);
    macsec_rx_sc_init(&rx_c);

    /* Peer B transmits under its own SCI with the shared SAK. */
    macsec_tx_sc_set_key(&tx_b, SAK, 16, SCI_B, 0, 1, 0, 1, 1);
    /* This channel belongs to a different peer. */
    macsec_rx_sc_set_key(&rx_c, SAK, 16, SCI, 0, 1, 0, 0);

    fails += expect_true(protect_one(&tx_b, frame, &flen) == 0,
                         "peer B frame built");
    fails += expect_true(macsec_rx(&rx_c, frame, flen, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_NO_SA,
                         "frame from another SCI is not accepted here");

    /* An AN this channel does not hold has no SA either. */
    macsec_tx_sc_init(&tx_b);
    macsec_tx_sc_set_key(&tx_b, SAK, 16, SCI, 2, 1, 0, 1, 1);
    fails += expect_true(protect_one(&tx_b, frame, &flen) == 0,
                         "AN 2 frame built");
    fails += expect_true(macsec_rx(&rx_c, frame, flen, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_NO_SA,
                         "frame under an uninstalled AN is not accepted");
    macsec_tx_sc_free(&tx_b);
    macsec_rx_sc_free(&rx_c);
    return fails;
}

/* The two keys live across a rekey carry independent packet-number
 * sequences, so their replay windows must be independent too: a burst on the
 * new key must not retroactively make the old key's in-flight frames look
 * like replays. */
static int test_per_sa_replay(void)
{
    struct macsec_tx_sc tx_old;
    struct macsec_tx_sc tx_new;
    struct macsec_rx_sc rx;
    uint8_t old_frame[FRAME_CAP];
    uint8_t new_frames[BURST][FRAME_CAP];
    uint8_t rec[FRAME_CAP];
    size_t  old_len = 0, rlen = 0;
    size_t  new_lens[BURST];
    int     i, fails = 0, ok = 1;

    printf("Test 9: per-SA replay windows\n");
    macsec_tx_sc_init(&tx_old);
    macsec_tx_sc_init(&tx_new);
    macsec_rx_sc_init(&rx);

    macsec_tx_sc_set_key(&tx_old, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_tx_sc_set_key(&tx_new, SAK2, 16, SCI, 1, 1, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 0 /* strict */, 0);
    macsec_rx_sc_set_key(&rx, SAK2, 16, SCI, 1, 1, 0, 0);

    /* One old-key frame at PN 1, held back as if delayed on the wire. */
    fails += expect_true(protect_one(&tx_old, old_frame, &old_len) == 0,
                         "old-key frame at PN 1 built");
    /* Meanwhile the new key runs a burst up to PN 8. */
    for (i = 0; i < BURST; i++) {
        if (protect_one(&tx_new, new_frames[i], &new_lens[i]) != 0
            || macsec_rx(&rx, new_frames[i], new_lens[i], rec, sizeof(rec),
                         &rlen) != MACSEC_RX_OK) {
            ok = 0;
        }
    }
    fails += expect_true(ok, "new-key burst accepted");
    /* The delayed old-key frame is still fresh on its own SA. */
    fails += expect_true(macsec_rx(&rx, old_frame, old_len, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_OK,
                         "old-key PN 1 not treated as a replay");
    /* But a genuine duplicate on that SA still is. */
    fails += expect_true(macsec_rx(&rx, old_frame, old_len, rec, sizeof(rec),
                         &rlen) == MACSEC_RX_REPLAY,
                         "duplicate on the old SA rejected");
    macsec_tx_sc_free(&tx_old);
    macsec_tx_sc_free(&tx_new);
    macsec_rx_sc_free(&rx);
    return fails;
}

int main(void)
{
    int fails = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    fails += test_in_order();
    fails += test_replay_window();
    fails += test_strict_mode();
    fails += test_integrity_only();
    fails += test_tamper();
    fails += test_pn_exhaustion();
    fails += test_two_key_window();
    fails += test_sci_demux();
    fails += test_per_sa_replay();

    printf("\n%s: macsec_sa (%d failure%s)\n",
           fails == 0 ? "PASS" : "FAIL", fails, fails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}
