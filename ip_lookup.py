"""
===========================================================
Live Asterisk Firewall

ip_lookup.py

Purpose:
    Geo-locate attacker IPs using the free ip-api.com API.
    Also maps international phone number prefixes to countries
    for Toll Fraud destination enrichment.

No API key required.
Rate limit : 45 requests / minute (free tier).

Author:
    Jai
===========================================================
"""

import requests

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query"

_cache = {}


def lookup_ip(ip):
    if not ip or ip == "UNKNOWN":
        return None

    if ip in _cache:
        return _cache[ip]

    try:
        resp = requests.get(IP_API_URL.format(ip=ip), timeout=4)
        data = resp.json()

        if data.get("status") == "success":
            _cache[ip] = data
            return data

        _cache[ip] = None
        return None

    except Exception:
        _cache[ip] = None
        return None


def format_ip_info(geo):
    if not geo:
        return "  Location : Not available (private/unknown IP)"

    lines = [
        f"  Country   : {geo.get('country', 'Unknown')} ({geo.get('countryCode', '?')})",
        f"  Region    : {geo.get('regionName', 'Unknown')}",
        f"  City      : {geo.get('city', 'Unknown')}",
        f"  ISP       : {geo.get('isp', 'Unknown')}",
        f"  Org       : {geo.get('org', 'Unknown')}",
        f"  AS        : {geo.get('as', 'Unknown')}",
    ]

    return "\n".join(lines)


PHONE_PREFIXES = {
    "1":   "USA / Canada",     "7":   "Russia / Kazakhstan",
    "20":  "Egypt",            "27":  "South Africa",
    "30":  "Greece",           "31":  "Netherlands",
    "32":  "Belgium",          "33":  "France",
    "34":  "Spain",            "36":  "Hungary",
    "39":  "Italy",            "40":  "Romania",
    "41":  "Switzerland",      "43":  "Austria",
    "44":  "United Kingdom",   "45":  "Denmark",
    "46":  "Sweden",           "47":  "Norway",
    "48":  "Poland",           "49":  "Germany",
    "51":  "Peru",             "52":  "Mexico",
    "53":  "Cuba",             "54":  "Argentina",
    "55":  "Brazil",           "56":  "Chile",
    "57":  "Colombia",         "58":  "Venezuela",
    "60":  "Malaysia",         "61":  "Australia",
    "62":  "Indonesia",        "63":  "Philippines",
    "64":  "New Zealand",      "65":  "Singapore",
    "66":  "Thailand",         "81":  "Japan",
    "82":  "South Korea",      "84":  "Vietnam",
    "86":  "China",            "90":  "Turkey",
    "91":  "India",            "92":  "Pakistan",
    "93":  "Afghanistan",      "94":  "Sri Lanka",
    "95":  "Myanmar",          "98":  "Iran",
    "212": "Morocco",          "213": "Algeria",
    "216": "Tunisia",          "218": "Libya",
    "234": "Nigeria",          "254": "Kenya",
    "255": "Tanzania",         "256": "Uganda",
    "263": "Zimbabwe",         "264": "Namibia",
    "380": "Ukraine",          "381": "Serbia",
    "385": "Croatia",          "386": "Slovenia",
    "420": "Czech Republic",   "421": "Slovakia",
    "880": "Bangladesh",       "886": "Taiwan",
    "960": "Maldives",         "961": "Lebanon",
    "962": "Jordan",           "963": "Syria",
    "964": "Iraq",             "965": "Kuwait",
    "966": "Saudi Arabia",     "967": "Yemen",
    "968": "Oman",             "971": "UAE",
    "972": "Israel",           "973": "Bahrain",
    "974": "Qatar",            "977": "Nepal",
    "992": "Tajikistan",       "993": "Turkmenistan",
    "994": "Azerbaijan",       "995": "Georgia",
    "996": "Kyrgyzstan",       "998": "Uzbekistan",
}


def lookup_phone_country(number):
    number = str(number).lstrip("+").strip()

    for length in (3, 2, 1):
        prefix = number[:length]
        if prefix in PHONE_PREFIXES:
            return PHONE_PREFIXES[prefix], "+" + prefix

    return "Unknown", "?"


if __name__ == "__main__":

    print("=" * 50)
    print("IP GEOLOCATION TEST")
    print("=" * 50)

    for ip in ["185.22.11.5", "91.55.77.22", "192.168.1.1", "UNKNOWN"]:
        print(f"\nLooking up: {ip}")
        print(format_ip_info(lookup_ip(ip)))

    print()
    print("=" * 50)
    print("PHONE NUMBER COUNTRY TEST")
    print("=" * 50)

    for num in ["919566704154", "441234567890", "12025551234"]:
        country, prefix = lookup_phone_country(num)
        print(f"\nNumber : +{num}  |  Prefix : {prefix}  |  Country : {country}")
