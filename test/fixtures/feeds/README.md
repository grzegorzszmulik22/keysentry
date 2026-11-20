# Feed fixtures

Recorded 2026-10-27 for phase 2 (incidents and corroboration). Real items are trimmed to title,
link, date and at most the first two sentences of the summary.

| File | Origin | Real or synthetic |
|---|---|---|
| `railway-official-2026-10.xml` | `https://blog.railway.com/rss.xml` (copied from `test/monitor/fixtures/railway-blog-2026-10.xml`, first five items): four security posts of 21–22 Oct 2026 and one tutorial | real |
| `news-thehackernews-railway.xml` | `https://feeds.feedburner.com/TheHackersNews`, item of 22 Oct 2026, plus one synthetic unrelated item | real + one synthetic |
| `news-bleepingcomputer-railway.xml` | article page `https://www.bleepingcomputer.com/news/security/railway-warns-devs-to-rotate-secrets-after-potential-breach/` (title, `og:description`, `datePublished` 2026-10-22T17:25:31-04:00); the item had already left the live feed | real |
| `news-synthetic-negatives.xml` | written for tests: an outage, a phishing campaign naming two platforms, and a breach at another company that is hosted on Railway | synthetic |

The Hacker News (owner: The Hacker News) and BleepingComputer (owner: BleepingComputer LLC) are independent
outlets. Neither the outage, the phishing story nor the other-company breach may trigger a rotation, even when
carried by two outlets.
