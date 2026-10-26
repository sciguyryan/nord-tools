# Maintaining the NordVPN low-ads catalogue

The built-in `low-ads` group is a **manually curated experimental shortlist**, not an authoritative list of advert-free countries. Its purpose is to find NordVPN OpenVPN locations worth benchmarking when a user wants to test whether YouTube serves fewer adverts. No country in this file is guaranteed to suppress advertising. Results may vary by IP address, account, video, device, session, time and YouTube policy.

## Evidence and selection rules

Use the following evidence in order, recording the date of each review:

1. **YouTube's official monetised markets**: https://support.google.com/youtube/answer/1342206. Countries absent from this list are plausible candidates, **not proven ad-free**. This page describes where advertisers can target monetised YouTube markets; it is not a live ad-delivery test. Do not include a country merely because a third-party website calls it ad-free.
2. **NordVPN's current locations**: https://nordvpn.com/servers/ and https://support.nordvpn.com/hc/en-us/articles/19383127694225-Where-can-I-find-the-NordVPN-server-list. A location listed here may not have a currently downloadable OpenVPN profile.
3. **NordVPN OpenVPN configurations**: use the project's official archive URL `https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip` and verify the exact country prefixes actually represented. Only include countries with usable `.ovpn` entries in the current archive.
4. **Independent observation**: prefer dated, reproducible tests with named countries and clear testing conditions. For example, the NordVPN-specific community report https://www.reddit.com/r/nordvpn/comments/1laeegr/no_yt_ads_while_connected_to_nordvpn_confirmed/ tested several servers per country, but remains anecdotal. Independent write-ups include https://www.top10vpn.com/guides/how-to-block-youtube-ads/ and https://www.cloudwards.net/block-ads-on-youtube/. Reports may be outdated or commercially motivated and do not override Google's current market information.

For inclusion, require a NordVPN OpenVPN profile and a plausible YouTube-specific reason to expect fewer adverts, preferably both absence from the monetised-market list and corroborating observations. The catalogue is deliberately selective: **not every non-monetised market is automatically included**. Do not include countries present on the official monetised-market list solely because a user once observed fewer adverts there.

## Curated locations (reviewed 22 October 2026)

The 17 included ISO country codes are:

| Code | Location | Supporting rationale |
| --- | --- | --- |
| `ad` | Andorra | Outside published monetised markets; independent low-ad reports |
| `al` | Albania | Outside published monetised markets; repeated independent and NordVPN-specific observations |
| `ao` | Angola | Outside published monetised markets; NordVPN-specific community observation |
| `bn` | Brunei | Outside published monetised markets; NordVPN-specific community observation |
| `bs` | Bahamas | Outside published monetised markets; independent and community observations |
| `bt` | Bhutan | Outside published monetised markets; independent and community observations |
| `bz` | Belize | Outside published monetised markets; independent and community observations |
| `gl` | Greenland | Outside published monetised markets; NordVPN-specific community observation |
| `im` | Isle of Man | Outside published monetised markets; NordVPN-specific community observation |
| `je` | Jersey | Outside published monetised markets; NordVPN-specific community observation |
| `mc` | Monaco | Outside published monetised markets; independent and community observations |
| `mm` | Myanmar | Outside published monetised markets; independent and community observations |
| `mn` | Mongolia | Outside published monetised markets; NordVPN-specific community observation |
| `mz` | Mozambique | Outside published monetised markets; NordVPN-specific community observation |
| `pg` | Papua New Guinea | Outside published monetised markets; NordVPN-specific community observation |
| `tt` | Trinidad and Tobago | Outside published monetised markets; NordVPN-specific community observation |
| `uz` | Uzbekistan | Outside published monetised markets; NordVPN-specific community observation |

All 17 prefixes appeared in the user-supplied NordVPN OpenVPN directory listing examined on 22 October 2026. This establishes **configuration presence at that point in time**, not current server reachability, physical location or observed advert suppression. Independent reports provide stronger corroboration for some entries than others.

**Not included despite community reports:** Armenia (`am`), Laos (`la`), Nepal (`np`) and Sri Lanka (`lk`) are listed in Google's published monetised markets. Keep them out of this particular shortlist unless fresh, repeatable testing justifies an explicitly documented exception. This avoids conflating occasional low ad delivery with non-monetised-market eligibility.

## How to review and update

1. Open Google's official monetised-market list and record the review date. Compare names carefully with ISO codes, noting spelling differences and NordVPN-specific aliases (`uk` normalises to `gb`).
2. Check NordVPN's server locations and **confirm OpenVPN availability**, rather than assuming every advertised location supports the selected protocol.
3. Download the official configuration archive, then extract its member filenames without unpacking the profiles:

   ```bash
   curl -fL https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip -o ovpn.zip
   unzip -Z -1 ovpn.zip > nordvpn-openvpn-files.txt
   grep -oE '[a-z]{2}[0-9]+\.nordvpn\.com' nordvpn-openvpn-files.txt \
     | sed -E 's/[0-9]+\.nordvpn\.com$//' | sort -u > nordvpn-openvpn-countries.txt
   ```

4. Compare each proposed country code with `nordvpn-openvpn-countries.txt`. For any new entry, record at least one supporting dated observation, ideally tested on several NordVPN endpoints and both signed-in and signed-out sessions. Verify whether the observed IP is geolocated as intended.
5. Edit **only** `region-lists.json` for the shortlist. Keep codes lowercase, unique and sorted. Do not hand-edit `country-names.json`, which is generated from `pycountry`.
6. Update this document's rationale and review date, then update the fixed expected set in `tests/test_benchmark.py`. Run `python -m unittest discover -s tests -v`, `ruff check .` and `ruff format --check --diff .` before committing.
7. Revisit the list when YouTube changes its monetised markets, NordVPN adds or removes locations, or credible repeatable tests contradict an entry. Remove locations that disappear from the current OpenVPN archive or become clearly unsuitable, documenting why.

**Scope:** The benchmarker's ICMP results measure network reachability and latency, **not YouTube advertising frequency**. A fast endpoint is not necessarily an endpoint with fewer adverts. Never describe this list as an ad blocker or promise that it bypasses adverts.
