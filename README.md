## Detection Logic & Approach
### Brute-Force Attempts
* **Method**: Filters login_failed events and applies a rolling 10-minute window.

* **Logic**: Groups by ip_address and counts consecutive failures.

* **Threshold**: Flagged if an IP generates 3 or more failures within 10 minutes.

* **Goal**: Detect automated password-guessing attacks.

### External Access Detection
* **Method**: Uses is_public_ip() with the ipaddress library.

* **Logic**: Checks if an IP is outside the private RFC 1918 ranges (e.g., 192.168.x.x).

* **Goal**: Identify access from the public internet, which carries higher risk.

### Impossible Travel (Geo-hop)
* **Method**: Uses groupby('user_id') and .shift(1) to compare consecutive logins.

* **Logic**: Compares the Network Prefix (first two octets) and the time difference.

* **Threshold**: Flagged if the prefix changes and time_diff is under 15 minutes.

* **Goal**: Detect account takeover where travel between locations is physically impossible.

### Assumptions
Logs are sorted by user_id and timestamp for accurate sequence analysis.

A change in the first two octets of an IP represents a significant network/location shift.

All legitimate internal traffic originates from standard private IP ranges.
