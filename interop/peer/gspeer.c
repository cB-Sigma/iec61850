/*
 * Copyright 2026 Abhinav Gautam
 * SPDX-License-Identifier: Apache-2.0
 *
 * GOOSE and sampled values peers on libiec61850 (github.com/mz-automation/
 * libiec61850, GPLv3) for the interop tests. Built and run only in a test
 * container; nothing of libiec61850 is distributed with the Go modules.
 *
 *   gspeer gpub <iface>        GOOSE publisher: APPID 0x1001 to
 *                              01:0C:CD:01:00:02, gocbRef
 *                              SIGMAPEER/LLN0$GO$gcb1, datSet
 *                              SIGMAPEER/LLN0$DS1, goID peerGoID, confRev 7,
 *                              timeAllowedToLive 2000; data set INT32,
 *                              BOOLEAN, FLOAT32, quality (13 bits)
 *       stdin: state <int> <0|1> <float>   new state (stNum + 1, sqNum 0)
 *              repeat                      retransmission (sqNum + 1)
 *   gspeer gsub <iface> <gocbRef> <appid>  GOOSE subscriber
 *   gspeer svsub <iface> <appid>           SV subscriber, data read as
 *                                          INT32 and quality pairs
 *   gspeer svpub <iface>       SV publisher: APPID 0x4001, svID peerSV,
 *                              datSet SIGMAPEER/LLN0$PhsMeas1, confRev 3,
 *                              four INT32 and quality pairs, smpSynch 2;
 *       stdin: send <smpCnt> <v0> <v1> <v2> <v3>
 *
 * Every event is printed on a line starting "PEER ".
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "goose_publisher.h"
#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "hal_thread.h"
#include "linked_list.h"
#include "mms_value.h"
#include "sv_publisher.h"
#include "sv_subscriber.h"

static void say(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

#include <stdarg.h>
static void
say(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("PEER ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static void
gooseListener(GooseSubscriber s, void* parameter)
{
    (void)parameter;
    char buf[2048];
    MmsValue* values = GooseSubscriber_getDataSetValues(s);
    buf[0] = 0;
    if (values)
        MmsValue_printToBuffer(values, buf, sizeof(buf));
    uint8_t src[6];
    GooseSubscriber_getSrcMac(s, src);
    say("goose stNum=%u sqNum=%u ttl=%u confRev=%u ndsCom=%d test=%d valid=%d err=%d appid=%u goID=%s datSet=%s "
        "gocbRef=%s ts=%llu n=%d values=%s",
        GooseSubscriber_getStNum(s), GooseSubscriber_getSqNum(s), GooseSubscriber_getTimeAllowedToLive(s),
        GooseSubscriber_getConfRev(s), GooseSubscriber_needsCommission(s), GooseSubscriber_isTest(s),
        GooseSubscriber_isValid(s), (int)GooseSubscriber_getParseError(s), GooseSubscriber_getAppId(s),
        GooseSubscriber_getGoId(s), GooseSubscriber_getDataSet(s), GooseSubscriber_getGoCbRef(s),
        (unsigned long long)GooseSubscriber_getTimestamp(s), values ? MmsValue_getArraySize(values) : -1, buf);
}

static void
svListener(SVSubscriber s, void* parameter, SVSubscriber_ASDU a)
{
    (void)s;
    (void)parameter;
    char line[1024];
    int n = snprintf(line, sizeof(line), "sv svID=%s datSet=%s smpCnt=%u confRev=%u smpSynch=%u size=%d",
                     SVSubscriber_ASDU_getSvId(a) ? SVSubscriber_ASDU_getSvId(a) : "",
                     SVSubscriber_ASDU_hasDatSet(a) ? SVSubscriber_ASDU_getDatSet(a) : "",
                     SVSubscriber_ASDU_getSmpCnt(a), SVSubscriber_ASDU_getConfRev(a), SVSubscriber_ASDU_getSmpSynch(a),
                     SVSubscriber_ASDU_getDataSize(a));
    int size = SVSubscriber_ASDU_getDataSize(a);
    for (int i = 0; i + 8 <= size && n < (int)sizeof(line) - 64; i += 8) {
        n += snprintf(line + n, sizeof(line) - n, " i%d=%d q%d=%04x", i / 8, SVSubscriber_ASDU_getINT32(a, i), i / 8,
                      (unsigned)SVSubscriber_ASDU_getQuality(a, i + 4));
    }
    say("%s", line);
}

static int
gpub(const char* iface)
{
    CommParameters p;
    memset(&p, 0, sizeof(p));
    p.appId = 0x1001;
    uint8_t mac[6] = {0x01, 0x0c, 0xcd, 0x01, 0x00, 0x02};
    memcpy(p.dstAddress, mac, 6);
    p.vlanPriority = 4;
    GoosePublisher pub = GoosePublisher_create(&p, iface);
    if (!pub) {
        say("ERROR publisher");
        return 1;
    }
    GoosePublisher_setGoCbRef(pub, "SIGMAPEER/LLN0$GO$gcb1");
    GoosePublisher_setDataSetRef(pub, "SIGMAPEER/LLN0$DS1");
    GoosePublisher_setGoID(pub, "peerGoID");
    GoosePublisher_setConfRev(pub, 7);
    GoosePublisher_setTimeAllowedToLive(pub, 2000);
    LinkedList ds = LinkedList_create();
    MmsValue* vInt = MmsValue_newIntegerFromInt32(0);
    MmsValue* vBool = MmsValue_newBoolean(false);
    MmsValue* vFloat = MmsValue_newFloat(0);
    MmsValue* vQ = MmsValue_newBitString(13);
    LinkedList_add(ds, vInt);
    LinkedList_add(ds, vBool);
    LinkedList_add(ds, vFloat);
    LinkedList_add(ds, vQ);
    bool first = true;
    say("READY");
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        int i, b;
        float f;
        if (sscanf(line, "state %d %d %f", &i, &b, &f) == 3) {
            MmsValue_setInt32(vInt, i);
            MmsValue_setBoolean(vBool, b != 0);
            MmsValue_setFloat(vFloat, f);
            MmsValue_setBitStringBit(vQ, 1, i < 0); /* validity invalid for a negative value */
            if (!first)
                GoosePublisher_increaseStNum(pub);
            first = false;
            say("sent rc=%d", GoosePublisher_publish(pub, ds));
        }
        else if (strncmp(line, "repeat", 6) == 0) {
            say("sent rc=%d", GoosePublisher_publish(pub, ds));
        }
        else if (strncmp(line, "quit", 4) == 0) {
            break;
        }
    }
    GoosePublisher_destroy(pub);
    return 0;
}

static int
svpub(const char* iface)
{
    CommParameters p;
    memset(&p, 0, sizeof(p));
    p.appId = 0x4001;
    uint8_t mac[6] = {0x01, 0x0c, 0xcd, 0x04, 0x00, 0x02};
    memcpy(p.dstAddress, mac, 6);
    p.vlanPriority = 4;
    SVPublisher pub = SVPublisher_create(&p, iface);
    if (!pub) {
        say("ERROR publisher");
        return 1;
    }
    SVPublisher_ASDU a = SVPublisher_addASDU(pub, "peerSV", "SIGMAPEER/LLN0$PhsMeas1", 3);
    int iv[4], iq[4];
    for (int k = 0; k < 4; k++) {
        iv[k] = SVPublisher_ASDU_addINT32(a);
        iq[k] = SVPublisher_ASDU_addQuality(a);
    }
    SVPublisher_setupComplete(pub);
    SVPublisher_ASDU_setSmpSynch(a, 2); /* writes into the buffer setupComplete made */
    say("READY");
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        int cnt, v[4];
        if (sscanf(line, "send %d %d %d %d %d", &cnt, &v[0], &v[1], &v[2], &v[3]) == 5) {
            for (int k = 0; k < 4; k++) {
                SVPublisher_ASDU_setINT32(a, iv[k], v[k]);
                SVPublisher_ASDU_setQuality(a, iq[k], k == 3 ? QUALITY_VALIDITY_QUESTIONABLE : QUALITY_VALIDITY_GOOD);
            }
            SVPublisher_ASDU_setSmpCnt(a, (uint16_t)cnt);
            SVPublisher_publish(pub);
            say("sent smpCnt=%d", cnt);
        }
        else if (strncmp(line, "quit", 4) == 0) {
            break;
        }
    }
    SVPublisher_destroy(pub);
    return 0;
}

int
main(int argc, char** argv)
{
    if (argc >= 3 && strcmp(argv[1], "gpub") == 0)
        return gpub(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "svpub") == 0)
        return svpub(argv[2]);
    if (argc >= 5 && strcmp(argv[1], "gsub") == 0) {
        GooseReceiver r = GooseReceiver_create();
        GooseReceiver_setInterfaceId(r, argv[2]);
        GooseSubscriber s = GooseSubscriber_create(argv[3], NULL);
        GooseSubscriber_setAppId(s, (uint16_t)strtol(argv[4], NULL, 0));
        GooseSubscriber_setListener(s, gooseListener, NULL);
        GooseReceiver_addSubscriber(r, s);
        GooseReceiver_start(r);
        if (!GooseReceiver_isRunning(r)) {
            say("ERROR receiver");
            return 1;
        }
        say("READY");
        char line[64];
        while (fgets(line, sizeof(line), stdin)) {
            if (strncmp(line, "quit", 4) == 0)
                break;
        }
        GooseReceiver_stop(r);
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "svsub") == 0) {
        SVReceiver r = SVReceiver_create();
        SVReceiver_setInterfaceId(r, argv[2]);
        SVSubscriber s = SVSubscriber_create(NULL, (uint16_t)strtol(argv[3], NULL, 0));
        SVSubscriber_setListener(s, svListener, NULL);
        SVReceiver_addSubscriber(r, s);
        SVReceiver_start(r);
        if (!SVReceiver_isRunning(r)) {
            say("ERROR receiver");
            return 1;
        }
        say("READY");
        char line[64];
        while (fgets(line, sizeof(line), stdin)) {
            if (strncmp(line, "quit", 4) == 0)
                break;
        }
        SVReceiver_stop(r);
        return 0;
    }
    fprintf(stderr, "usage: gspeer gpub|svpub <iface> | gsub <iface> <gocbRef> <appid> | svsub <iface> <appid>\n");
    return 2;
}
