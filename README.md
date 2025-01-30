## DAMUKOON: Wireless DDoS Attack Framework

**AUTHOR:**
Rip70022/craxterpy

**Description:**

`DAMUKOON` is a `wireless DDoS attack framework` that `utilizes` multi-vector `attack techniques` to `overwhelm wireless networks`. This `Python` script uses the `Scapy library` to send `malicious network packets` and `overwhelm` the `target network`.

**Features:**

* **Multi-vector attack**: `DAMUKOON` uses `multiple attack techniques` to `overwhelm the target network`, including `deauthentication attacks`, `beacon spam`, `authentication floods`, and probe response `floods`.
* **Wireless network support**: `DAMUKOON` is `compatible` with `IEEE 802.11 a/b/g/n/ac/ax` wireless `networks`.
* **Aggressive attack mode**: `DAMUKOON` uses an `aggressive attack mode` to `overwhelm` the `target network` as quickly as possible.
* **Wireless interface support**: `DAMUKOON` is `compatible` with `wireless interfaces` in `monitor mode`.
* **Requirements**: `DAMUKOON` requires `Python 3.10+`, `root` privileges, a `wireless interface` in `monitor mode`, and the `Scapy library`.

**Usage:**

1. Install the required dependencies (`Scapy`).
```
pip install scapy
```
3. `Run` the `DAMUKOON` script.
```
cd https://github.com/Rip70022/DAMUKOON
sudo python3 DAMUKOON.py
```
5. Configure the `wireless interface` and `target BSSID`.
6. `Start` the `attack`.

**License:**

This `project` is `licensed` under the `MIT License`.

**Warning:**

The `author` is not `responsible` for `any damage` caused by `unauthorized use` of this `script`.

**System Requirements:**

* `Linux`
* `Python 3.10+`
* `Root` privileges
* `Wireless interface` in `monitor mode`
* `Scapy library`

**Execution Notes:**

1. Requires `monitor mode`:
```
airmon-ng start wlan0
```
3. Find the target BSSID:
```
 airodump-ng wlan0mon
```
5. Tested on Kali `1/30/2025` with `Atheros AR9271 chipset`
6. Optimal `performance` requires `5GHz` capable `hardware`
7. Combine with:
```
 mdk4 wlan0mon d -c <channel>
```

**Disclaimer:**

This `script` demonstrates `wireless network vulnerabilities`. Use `only` on `networks you own` or `have explicit permission` to `test`. The `author` assumes `no` `liability` for `unauthorized use`. `Violators` will be `tracked`, `hacked`, and `reported` to the `Cyber Police`. Consequences will `never` be the `same`.
