// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package goose encodes and decodes IEC 61850-8-1 GOOSE and IEC 61850-9-2
// sampled values frames (Ethernet, 802.1Q, HSR and PRP), classifies
// stNum/sqNum arrivals, publishes GOOSE with the retransmission scheme of
// IEC 61850-8-1 18.1.2.5 (Publisher) and sampled values streams
// (SVStream), carries routable GOOSE and SV over UDP (IEC 61850-8-1
// Annex J), and applies IEC 62351-6 security: the Layer 2 extension and
// secured routable SPDUs with HMAC, AES-GMAC and AES-GCM/CBC keys held in
// a KeyStore.
//
// Capturing and sending on a network interface needs raw sockets, which
// are platform and privilege specific; the package only defines Source
// and Sink, with pcap implementations (OpenPcap, NewPcapWriter,
// CreatePcapSink). An application supplies its own capture (AF_PACKET,
// say) behind those interfaces. Key distribution (IEC 62351-9 GDOI) is
// the application's too: delivered keys go in with KeyStore.Deliver.
package goose
