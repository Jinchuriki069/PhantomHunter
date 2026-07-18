#!/usr/bin/env python3
"""PhantomHunter v2.2 - Phone, Email & Username Reconnaissance
Cross-platform: Termux, Kali Linux, Ubuntu, macOS, WSL
"""

import asyncio
import aiohttp
import dns.resolver
import hashlib
import os
import re
import sys
import socket
from urllib.parse import quote
from datetime import datetime

__version__ = "2.2.0"
__author__ = "PHARAOH"

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ANSI Colors
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

def c(color, text):
    return f"{color}{text}{C.END}"

def detect_target_type(target):
    target = target.strip()
    if re.match(r'^[\+\d\s\-\(\)\.]{7,}$', target) and re.search(r'\d', target):
        return 'PHONE'
    elif re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
        return 'EMAIL'
    return 'USERNAME'

def normalize_phone(phone):
    digits = re.sub(r'[^\d]', '', phone)
    if len(digits) == 10 and not phone.startswith('+'):
        digits = '1' + digits
    if not digits.startswith('+'):
        digits = '+' + digits
    return digits

def parse_phone_info(phone):
    digits = re.sub(r'[^\d]', '', phone)
    if len(digits) == 11 and digits.startswith('1'):
        return {
            'country_code': '+1',
            'area_code': digits[1:4],
            'local': f"{digits[4:7]}-{digits[7:]}",
            'country': 'United States / Canada / Caribbean',
            'normalized': f"+{digits}"
        }
    return {
        'country_code': '+' + digits[:-10] if len(digits) > 10 else '+?',
        'area_code': digits[-10:-7] if len(digits) >= 10 else '???',
        'local': f"{digits[-7:-4]}-{digits[-4:]}" if len(digits) >= 10 else digits,
        'country': 'Unknown',
        'normalized': f"+{digits}"
    }

SITES = {
    'Instagram': 'https://instagram.com/{u}',
    'Twitter/X': 'https://twitter.com/{u}',
    'Facebook': 'https://facebook.com/{u}',
    'TikTok': 'https://tiktok.com/@{u}',
    'Snapchat': 'https://snapchat.com/add/{u}',
    'Pinterest': 'https://pinterest.com/{u}',
    'Reddit': 'https://reddit.com/user/{u}',
    'Tumblr': 'https://{u}.tumblr.com',
    'LinkedIn': 'https://linkedin.com/in/{u}',
    'GitHub': 'https://github.com/{u}',
    'GitLab': 'https://gitlab.com/{u}',
    'Bitbucket': 'https://bitbucket.org/{u}',
    'Dev.to': 'https://dev.to/{u}',
    'YouTube': 'https://youtube.com/@{u}',
    'Twitch': 'https://twitch.tv/{u}',
    'Spotify': 'https://open.spotify.com/user/{u}',
    'SoundCloud': 'https://soundcloud.com/{u}',
    'Medium': 'https://medium.com/@{u}',
    'Substack': 'https://{u}.substack.com',
    'WordPress': 'https://{u}.wordpress.com',
    'Blogger': 'https://{u}.blogspot.com',
    'Steam': 'https://steamcommunity.com/id/{u}',
    'Roblox': 'https://roblox.com/user.aspx?username={u}',
    'Minecraft': 'https://namemc.com/profile/{u}',
    'Discord': 'https://discord.com/users/{u}',
    'Keybase': 'https://keybase.io/{u}',
    'Gravatar': 'https://gravatar.com/{u}',
    'Linktree': 'https://linktr.ee/{u}',
    'Pastebin': 'https://pastebin.com/u/{u}',
    'TryHackMe': 'https://tryhackme.com/p/{u}',
    'HackTheBox': 'https://hackthebox.com/users/{u}',
    'HackerNews': 'https://news.ycombinator.com/user?id={u}',
    'LeetCode': 'https://leetcode.com/{u}',
    'Kaggle': 'https://kaggle.com/{u}',
    'Replit': 'https://replit.com/@{u}',
    'Docker Hub': 'https://hub.docker.com/u/{u}',
    'npm': 'https://npmjs.com/~{u}',
    'PyPI': 'https://pypi.org/user/{u}',
    'Behance': 'https://behance.net/{u}',
    'Dribbble': 'https://dribbble.com/{u}',
    'ArtStation': 'https://artstation.com/{u}',
    'DeviantArt': 'https://{u}.deviantart.com',
    'Flickr': 'https://flickr.com/people/{u}',
    'Unsplash': 'https://unsplash.com/@{u}',
    'Imgur': 'https://imgur.com/user/{u}',
    'AngelList': 'https://angel.co/{u}',
    'ProductHunt': 'https://producthunt.com/@{u}',
    'About.me': 'https://about.me/{u}',
    'Etsy': 'https://etsy.com/shop/{u}',
    'eBay': 'https://ebay.com/usr/{u}',
    'Patreon': 'https://patreon.com/{u}',
    'Ko-fi': 'https://ko-fi.com/{u}',
    'Bandcamp': 'https://bandcamp.com/{u}',
    'Vimeo': 'https://vimeo.com/{u}',
    'Genius': 'https://genius.com/{u}',
    'Wattpad': 'https://wattpad.com/user/{u}',
    'Goodreads': 'https://goodreads.com/{u}',
    'Wikipedia': 'https://en.wikipedia.org/wiki/User:{u}',
    'Fandom': 'https://community.fandom.com/wiki/User:{u}',
    'OpenSea': 'https://opensea.io/{u}',
    'Etherscan': 'https://etherscan.io/address/{u}',
    'BitcoinTalk': 'https://bitcointalk.org/index.php?action=profile;u={u}',
    'Crunchbase': 'https://crunchbase.com/person/{u}',
    'SlideShare': 'https://slideshare.net/{u}',
    'Quora': 'https://quora.com/profile/{u}',
    'Mastodon': 'https://mastodon.social/@{u}',
    'Threads': 'https://threads.net/@{u}',
    'Bluesky': 'https://bsky.app/profile/{u}',
    'Vero': 'https://vero.co/{u}',
    'CodePen': 'https://codepen.io/{u}',
    'StackOverflow': 'https://stackoverflow.com/users/{u}',
    'GitHub Gist': 'https://gist.github.com/{u}',
    'SourceForge': 'https://sourceforge.net/u/{u}',
    'Launchpad': 'https://launchpad.net/~{u}',
    'RubyGems': 'https://rubygems.org/profiles/{u}',
    'Crates.io': 'https://crates.io/users/{u}',
    'CPAN': 'https://metacpan.org/author/{u}',
    'Packagist': 'https://packagist.org/users/{u}',
    'Hex.pm': 'https://hex.pm/users/{u}',
    'Terraform': 'https://registry.terraform.io/namespaces/{u}',
    'Ansible': 'https://galaxy.ansible.com/{u}',
    'Vagrant': 'https://app.vagrantup.com/{u}',
    'Dailymotion': 'https://dailymotion.com/{u}',
    'Mixcloud': 'https://mixcloud.com/{u}',
    'Last.fm': 'https://last.fm/user/{u}',
    'Musixmatch': 'https://musixmatch.com/user/{u}',
    'Newgrounds': 'https://{u}.newgrounds.com',
    'Itch.io': 'https://itch.io/profile/{u}',
    'GameJolt': 'https://gamejolt.com/@{u}',
    'Ghost': 'https://{u}.ghost.io',
    'Hashnode': 'https://hashnode.com/@{u}',
    'Devpost': 'https://devpost.com/{u}',
    'Write.as': 'https://write.as/{u}',
    'Xbox': 'https://xboxgamertag.com/search/{u}',
    'PlayStation': 'https://psnprofiles.com/{u}',
    'Guilded': 'https://guilded.gg/profile/{u}',
    'Faceit': 'https://faceit.com/en/players/{u}',
    'AO3': 'https://archiveofourown.org/users/{u}',
    'Fanfiction': 'https://fanfiction.net/~{u}',
    'Miraheze': 'https://meta.miraheze.org/wiki/User:{u}',
    'Lemmy': 'https://lemmy.world/u/{u}',
    'SaidIt': 'https://saidit.net/user/{u}',
    'Lens': 'https://lenster.xyz/u/{u}',
    'Mirror': 'https://mirror.xyz/{u}',
    '500px': 'https://500px.com/{u}',
    'Pexels': 'https://pexels.com/@{u}',
    'Pixabay': 'https://pixabay.com/users/{u}',
    'Giphy': 'https://giphy.com/{u}',
    'Carrd': 'https://{u}.carrd.co',
    'Bio.link': 'https://bio.link/{u}',
    'Beacons': 'https://beacons.ai/{u}',
    'Shopify': 'https://{u}.myshopify.com',
    'Gumroad': 'https://gumroad.com/{u}',
    'Buy Me a Coffee': 'https://buymeacoffee.com/{u}',
    'Liberapay': 'https://liberapay.com/{u}',
    'Open Collective': 'https://opencollective.com/{u}',
    'Bandcamp Artist': 'https://{u}.bandcamp.com',
    'Apple Music': 'https://music.apple.com/artist/{u}',
    'Deezer': 'https://deezer.com/profile/{u}',
    'Discogs': 'https://discogs.com/artist/{u}',
    'AllMusic': 'https://allmusic.com/artist/{u}',
    'RateYourMusic': 'https://rateyourmusic.com/~{u}',
    'MusicBrainz': 'https://musicbrainz.org/artist/{u}',
    'Songkick': 'https://songkick.com/artists/{u}',
    'Bandsintown': 'https://bandsintown.com/{u}',
    'Resident Advisor': 'https://residentadvisor.net/dj/{u}',
    'Beatport': 'https://beatport.com/artist/{u}',
    'Wikidata': 'https://wikidata.org/wiki/User:{u}',
    'Wikimedia': 'https://commons.wikimedia.org/wiki/User:{u}',
    'Phabricator': 'https://phabricator.wikimedia.org/p/{u}',
    'Gerrit': 'https://gerrit.wikimedia.org/r/q/owner:{u}',
    'Cloud VPS': 'https://wikitech.wikimedia.org/wiki/User:{u}',
    'Quarry': 'https://quarry.wmflabs.org/{u}',
    'VulnHub': 'https://vulnhub.com/user/{u}',
    'PentesterLab': 'https://pentesterlab.com/users/{u}',
    'PortSwigger': 'https://portswigger.net/users/{u}',
}

def get_mx(domain):
    try:
        return [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, 'MX')]
    except:
        return []

def get_spf(domain):
    try:
        return [str(r).strip('"') for r in dns.resolver.resolve(domain, 'TXT') if str(r).strip('"').startswith('v=spf1')]
    except:
        return []

def get_dmarc(domain):
    try:
        for r in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
            txt = str(r).strip('"')
            if txt.startswith('v=DMARC1'):
                return txt
    except:
        pass
    return None

def get_ns(domain):
    try:
        return [str(r).rstrip('.') for r in dns.resolver.resolve(domain, 'NS')]
    except:
        return []

def get_a(domain):
    try:
        return [str(r) for r in dns.resolver.resolve(domain, 'A')]
    except:
        return []

def get_ptr(ip):
    try:
        rev = dns.reversename.from_address(ip)
        return [str(r).rstrip('.') for r in dns.resolver.resolve(rev, 'PTR')]
    except:
        return []

def check_disposable(domain):
    d = [
        'tempmail.com', 'throwawaymail.com', 'guerrillamail.com', 'mailinator.com',
        'yopmail.com', 'sharklasers.com', '10minutemail.com', 'burnermail.io',
        'temp-mail.org', 'mailnesia.com', 'mailcatch.com', 'mohmal.com',
        'tempmailaddress.com', 'throwaway.email', 'trashmail.com',
        'mytrashmail.com', 'mailforspam.com', 'spamgourmet.com',
        'jetable.org', 'mailexpire.com', 'mailme.lv', 'mailzilla.com',
        'tempmail.net', 'tempmail.de', 'tempmail.co', 'tempmail.plus',
        'tempmail.ninja', 'tempmail.ws', 'tempmail.info',
        'protonmail.com', 'tutanota.com', 'mailbox.org', 'startmail.com',
        'countermail.com', 'runbox.com', 'kolabnow.com', 'mailfence.com',
        'anonaddy.com', 'simplelogin.com', 'addy.io', 'duck.com', 'mozmail.com',
        'mail.tm', 'mail.gw', 'tempail.com', 'emailondeck.com',
        'guerrillamail.net', 'maildrop.cc', 'harakirimail.com',
        'getnada.com', 'grr.la', 'pokemail.net', 'spam4.me', 'trbvm.com'
    ]
    return any(x in domain.lower() for x in d)

def derive_usernames(email):
    p = email.split('@')[0]
    v = {p}
    for sep in ['.', '_', '-', '+']:
        if sep in p:
            parts = p.split(sep)
            v.update([parts[0], parts[-1], ''.join(parts)])
    base = re.sub(r'\d+$', '', p)
    if base and base != p:
        v.add(base)
    v.update([p.lower(), p.upper(), p.capitalize()])
    if '.' in p:
        parts = p.split('.')
        v.update([parts[0], parts[-1], parts[0][0] + parts[-1], parts[0] + parts[-1][0]])
    if '_' in p:
        parts = p.split('_')
        v.update([parts[0], parts[-1], parts[0] + parts[-1]])
    if '-' in p:
        parts = p.split('-')
        v.update([parts[0], parts[-1], parts[0] + parts[-1]])
    return sorted(list(v))

def patterns(domain):
    return [
        f'{{f}}.{{l}}@{domain}',
        f'{{f}}{{l}}@{domain}',
        f'{{f}}_{{l}}@{domain}',
        f'{{f}}-{{l}}@{domain}',
        f'{{f}}{{l[0]}}@{domain}',
        f'{{f[0]}}{{l}}@{domain}',
        f'{{f}}@{domain}',
        f'{{l}}@{domain}'
    ]

async def check_gravatar(s, email):
    h = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        async with s.get(
            f'https://www.gravatar.com/{h}.json',
            timeout=aiohttp.ClientTimeout(total=5),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                d = await r.json()
                if d and 'entry' in d and len(d['entry']) > 0:
                    e = d['entry'][0]
                    return {
                        'found': True,
                        'name': e.get('displayName', ''),
                        'photo': e.get('thumbnailUrl', ''),
                        'profile': e.get('profileUrl', ''),
                        'urls': [u.get('value', '') for u in e.get('urls', [])],
                        'location': e.get('currentLocation', ''),
                        'about': e.get('aboutMe', '')[:300]
                    }
    except:
        pass
    return {'found': False}

async def check_github_email(s, email):
    try:
        async with s.get(
            f'https://api.github.com/search/commits?q=author-email:{quote(email)}',
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github.cloak-preview'}
        ) as r:
            if r.status == 200:
                d = await r.json()
                c = d.get('total_count', 0)
                if c > 0:
                    items = d.get('items', [])[:5]
                    repos = list(set([item.get('repository', {}).get('full_name', '?') for item in items]))
                    return {'found': True, 'commit_count': c, 'repos': repos}
            elif r.status == 403:
                return {'found': False, 'error': 'Rate limited'}
    except Exception as e:
        return {'found': False, 'error': str(e)}
    return {'found': False}

async def check_github_user(s, username):
    try:
        async with s.get(
            f'https://api.github.com/users/{username}',
            timeout=aiohttp.ClientTimeout(total=5),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                d = await r.json()
                return {
                    'found': True,
                    'login': d.get('login'),
                    'name': d.get('name'),
                    'company': d.get('company'),
                    'blog': d.get('blog'),
                    'location': d.get('location'),
                    'bio': d.get('bio'),
                    'public_repos': d.get('public_repos', 0),
                    'followers': d.get('followers', 0),
                    'created_at': d.get('created_at'),
                    'avatar': d.get('avatar_url'),
                    'url': d.get('html_url')
                }
            elif r.status == 404:
                return {'found': False}
    except:
        pass
    return {'found': False}

async def check_emailrep(s, email):
    try:
        async with s.get(
            f'https://emailrep.io/query/{quote(email)}',
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': USER_AGENT, 'Key': 'free'}
        ) as r:
            if r.status == 200:
                d = await r.json()
                det = d.get('details', {})
                return {
                    'found': True,
                    'reputation': d.get('reputation', ''),
                    'suspicious': d.get('suspicious', False),
                    'references': d.get('references', 0),
                    'blacklisted': det.get('blacklisted', False),
                    'malicious': det.get('malicious_activity', False),
                    'spoofable': det.get('spoofable', False),
                    'spam': det.get('spam', False),
                    'free_provider': det.get('free_provider', False),
                    'disposable': det.get('disposable', False),
                    'domain_exists': det.get('domain_exists', False),
                    'mx_records': det.get('mx_records', False),
                    'smtp_server': det.get('smtp_server', False),
                    'dmarc_enforced': det.get('dmarc_enforced', False)
                }
    except:
        pass
    return {'found': False}

async def check_google(s, email):
    res = {}
    try:
        async with s.get(
            f'https://picasaweb.google.com/data/entry/api/user/{quote(email)}?alt=json',
            timeout=aiohttp.ClientTimeout(total=5),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            res['picasa'] = r.status == 200
    except:
        res['picasa'] = False
    try:
        async with s.get(
            f'https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn&Email={quote(email)}',
            timeout=aiohttp.ClientTimeout(total=5),
            headers={'User-Agent': USER_AGENT},
            allow_redirects=False
        ) as r:
            res['account_redirect'] = r.status in [302, 303]
    except:
        res['account_redirect'] = False
    return res

async def check_hibp_breach(s, email):
    api_key = os.environ.get('HIBP_API_KEY', '')
    headers = {'User-Agent': USER_AGENT}
    if api_key:
        headers['hibp-api-key'] = api_key
    try:
        async with s.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}',
            timeout=aiohttp.ClientTimeout(total=10),
            headers=headers
        ) as r:
            if r.status == 200:
                d = await r.json()
                return {'found': True, 'breaches': [b.get('Name', '?') for b in d], 'count': len(d)}
            elif r.status == 404:
                return {'found': False, 'note': 'No breaches found'}
    except:
        pass
    return {'found': False, 'note': 'Could not check'}

async def check_hibp_paste(s, email):
    api_key = os.environ.get('HIBP_API_KEY', '')
    headers = {'User-Agent': USER_AGENT}
    if api_key:
        headers['hibp-api-key'] = api_key
    try:
        async with s.get(
            f'https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}',
            timeout=aiohttp.ClientTimeout(total=10),
            headers=headers
        ) as r:
            if r.status == 200:
                return {'found': True, 'pastes': len(await r.json())}
            elif r.status == 404:
                return {'found': False, 'note': 'No pastes found'}
    except:
        pass
    return {'found': False, 'note': 'Could not check'}

async def check_social(s, platform, url):
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'DNT': '1'
    }
    try:
        async with s.get(
            url,
            timeout=aiohttp.ClientTimeout(total=8),
            headers=headers,
            allow_redirects=True
        ) as r:
            status, final = r.status, str(r.url)
            if status == 200:
                if 'login' in final.lower() or 'auth' in final.lower():
                    return {'platform': platform, 'url': url, 'status': 'likely_exists', 'code': status}
                return {'platform': platform, 'url': url, 'status': 'found', 'code': status}
            elif status == 404:
                return {'platform': platform, 'url': url, 'status': 'not_found', 'code': status}
            elif status == 429:
                return {'platform': platform, 'url': url, 'status': 'rate_limited', 'code': status}
            elif status == 451:
                return {'platform': platform, 'url': url, 'status': 'blocked_region', 'code': status}
            else:
                return {'platform': platform, 'url': url, 'status': 'unknown', 'code': status}
    except asyncio.TimeoutError:
        return {'platform': platform, 'url': url, 'status': 'timeout', 'code': 0}
    except Exception as e:
        return {'platform': platform, 'url': url, 'status': 'error', 'error': str(e)[:40]}

async def check_keybase(s, username):
    try:
        async with s.get(
            f'https://keybase.io/{username}',
            timeout=aiohttp.ClientTimeout(total=5),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                text = await r.text()
                if username.lower() in text.lower() and 'not found' not in text.lower():
                    return {'found': True, 'url': f'https://keybase.io/{username}'}
    except:
        pass
    return {'found': False}

async def check_pastebin(s, email):
    try:
        async with s.get(
            f'https://psbdmp.ws/api/v3/search/{email}',
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                d = await r.json()
                if d and d.get('data'):
                    return {'found': True, 'count': len(d['data'])}
    except:
        pass
    return {'found': False}

async def check_domain_age(s, domain):
    try:
        async with s.get(
            f'https://rdap.org/domain/{domain}',
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                d = await r.json()
                events = d.get('events', [])
                created = next((e.get('eventDate', '') for e in events if e.get('eventAction') == 'registration'), '')
                updated = next((e.get('eventDate', '') for e in events if e.get('eventAction') == 'last update'), '')
                expires = next((e.get('eventDate', '') for e in events if e.get('eventAction') == 'expiration'), '')
                registrar = 'Unknown'
                for e in d.get('entities', []):
                    vcard = e.get('vcardArray', [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == 'fn':
                                registrar = item[3]
                                break
                return {
                    'found': True,
                    'registrar': registrar,
                    'created': created,
                    'updated': updated,
                    'expires': expires
                }
    except:
        pass
    return {'found': False}

async def check_ipinfo(s, domain):
    try:
        ip = socket.gethostbyname(domain)
        async with s.get(
            f'https://ipinfo.io/{ip}/json',
            timeout=aiohttp.ClientTimeout(total=5),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                d = await r.json()
                return {
                    'found': True,
                    'ip': ip,
                    'hostname': d.get('hostname'),
                    'org': d.get('org'),
                    'city': d.get('city'),
                    'region': d.get('region'),
                    'country': d.get('country'),
                    'loc': d.get('loc')
                }
    except:
        pass
    return {'found': False}

async def check_phone_api(s, phone):
    results = {}
    try:
        async with s.get(
            f'https://phonevalidation.abstractapi.com/v1/?api_key=free&phone={quote(phone)}',
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                d = await r.json()
                results['abstract'] = {
                    'valid': d.get('valid'),
                    'carrier': d.get('carrier'),
                    'line_type': d.get('line_type'),
                    'location': d.get('location'),
                    'country': d.get('country', {}).get('name')
                }
    except:
        pass
    return results

async def check_subdomains(s, domain):
    common = [
        'www', 'mail', 'ftp', 'admin', 'api', 'app', 'blog', 'cdn', 'chat', 'cloud',
        'cms', 'crm', 'db', 'dev', 'dns', 'docs', 'download', 'email', 'en', 'es',
        'fr', 'forum', 'gateway', 'git', 'help', 'host', 'img', 'jobs', 'lb', 'login',
        'm', 'media', 'mobile', 'mx', 'mx1', 'mx2', 'news', 'ns', 'ns1', 'ns2', 'old',
        'panel', 'pop', 'portal', 'remote', 'secure', 'server', 'shop', 'smtp', 'ssh',
        'ssl', 'stage', 'staging', 'static', 'stats', 'status', 'store', 'support',
        'test', 'upload', 'vpn', 'vps', 'web', 'webmail', 'wiki', 'ww1', 'ww2',
        'www1', 'www2'
    ]
    found = []
    for sub in common:
        try:
            full = f'{sub}.{domain}'
            socket.gethostbyname(full)
            found.append(full)
        except:
            pass
    return found

async def check_crtsh(s, domain):
    try:
        async with s.get(
            f'https://crt.sh/?q={domain}&output=json',
            timeout=aiohttp.ClientTimeout(total=15),
            headers={'User-Agent': USER_AGENT}
        ) as r:
            if r.status == 200:
                d = await r.json()
                subs = set()
                for entry in d[:50]:
                    name = entry.get('name_value', '')
                    if name and '*' not in name:
                        subs.add(name.strip().lower())
                return {'found': True, 'subdomains': sorted(list(subs))[:30]}
    except:
        pass
    return {'found': False}

def dorks(email, username, domain):
    return [
        f'site:pastebin.com "{email}"',
        f'site:github.com "{email}"',
        f'site:gitlab.com "{email}"',
        f'"{email}" filetype:pdf',
        f'"{email}" filetype:doc',
        f'"{email}" inurl:admin',
        f'"{email}" inurl:login',
        f'site:linkedin.com "{username}"',
        f'site:twitter.com "{username}"',
        f'intitle:"index of" "{domain}"',
        f'site:{domain} filetype:sql',
        f'site:{domain} inurl:wp-admin',
        f'site:{domain} ext:log',
        f'site:{domain} ext:env',
        f'site:{domain} ext:backup'
    ]

def shodan_queries(domain, ip):
    return [
        f'hostname:{domain}',
        f'ip:{ip}',
        f'ssl.cert.subject.cn:{domain}',
        f'http.html:"{domain}"',
        f'port:80 hostname:{domain}',
        f'port:443 hostname:{domain}',
        f'port:8080 hostname:{domain}',
        f'port:22 hostname:{domain}',
        f'port:3306 hostname:{domain}',
        f'port:27017 hostname:{domain}'
    ]

def cached(username, email):
    return {
        'Wayback (username)': f'https://web.archive.org/web/*/{username}',
        'Wayback (email)': f'https://web.archive.org/web/*/{email}',
        'Google Cache (username)': f'https://webcache.googleusercontent.com/search?q=cache:{username}',
        'Google Cache (email)': f'https://webcache.googleusercontent.com/search?q=cache:{email}'
    }

async def scan_phone(s, phone_raw):
    phone = normalize_phone(phone_raw)
    info = parse_phone_info(phone)
    print(f"\n{'='*70}")
    print(c(C.BOLD + C.CYAN, "  📱 PHANTOMHUNTER v2.2 — Phone Reconnaissance"))
    print(c(C.CYAN, f"  Target: {info['normalized']}"))
    print(c(C.CYAN, f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(f"{'='*70}\n")
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  📋 PHONE ANALYSIS"))
    print(f"{'─'*70}")
    print(f"  Valid Format: {c(C.GREEN, 'YES')}")
    print(f"  Normalized: {info['normalized']}")
    print(f"  Country: {info['country']}")
    print(f"  Country Code: {info['country_code']}")
    print(f"  Area Code: {info['area_code']}")
    print(f"  Local Number: {info['local']}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🌐 PHONE API LOOKUP"))
    print(f"{'─'*70}")
    phone_info = await check_phone_api(s, phone)
    if phone_info:
        for src, data in phone_info.items():
            print(f"  [{src}] Valid: {data.get('valid', '?')} | Carrier: {data.get('carrier', '?')} | Type: {data.get('line_type', '?')} | Country: {data.get('country', '?')}")
    else:
        print(f"  ⚠️ No API results (paid APIs like Numverify/Twilio recommended)")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🛠️ OSINT TOOLS & QUERIES"))
    print(f"{'─'*70}")
    print(f"  [Phone Search]:")
    print(f"    • Truecaller: https://www.truecaller.com/search/{phone.lstrip('+')}")
    print(f"    • NumLookup: https://www.numlookup.com/")
    print(f"    • Whitepages: https://www.whitepages.com/phone/{phone.lstrip('+')}")
    print(f"    • Spokeo: https://www.spokeo.com/search?q={phone}")
    print(f"    • Sync.me: https://sync.me/search/?number={phone.lstrip('+')}")
    print(f"    • CallerIDTest: https://calleridtest.com/{phone.lstrip('+')}")
    print()
    print(f"{'='*70}")
    print(c(C.GREEN + C.BOLD, "  ✅ PHONE SCAN COMPLETE"))
    print(f"{'='*70}\n")

async def scan_username(s, username):
    print(f"\n{'='*70}")
    print(c(C.BOLD + C.CYAN, "  👤 PHANTOMHUNTER v2.2 — Username Reconnaissance"))
    print(c(C.CYAN, f"  Target: {username}"))
    print(c(C.CYAN, f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(f"{'='*70}\n")
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  💻 GITHUB PROFILE"))
    print(f"{'─'*70}")
    gh = await check_github_user(s, username)
    if gh['found']:
        print(f"  ✅ {gh['login']}")
        print(f"     Name: {gh.get('name', '')} | Company: {gh.get('company', '')} | Location: {gh.get('location', '')}")
        print(f"     Repos: {gh['public_repos']} | Followers: {gh['followers']} | Created: {gh.get('created_at', '')}")
        print(f"     URL: {gh['url']}")
    else:
        print(f"  ❌ No exact match for '{username}'")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🔑 KEYBASE"))
    print(f"{'─'*70}")
    kb = await check_keybase(s, username)
    print(f"  {'✅ ' + kb['url'] if kb['found'] else '❌ Not found'}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🌐 SHERLOCK HUNT (100+ Sites)"))
    print(f"{'─'*70}")
    tasks = [check_social(s, p, u.replace('{u}', username)) for p, u in SITES.items()]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r['status'] == 'found']
    likely = [r for r in results if r['status'] == 'likely_exists']
    notfound = [r for r in results if r['status'] == 'not_found']
    blocked = [r for r in results if r['status'] not in ['found', 'likely_exists', 'not_found']]
    if found:
        print(f"  {c(C.GREEN, '✅ FOUND (' + str(len(found)) + '):')}")
        for p in found[:20]:
            print(f"     • {p['platform']}: {p['url']}")
        if len(found) > 20:
            print(f"     ... and {len(found) - 20} more")
    if likely:
        print(f"\n  {c(C.YELLOW, '🟡 LIKELY (' + str(len(likely)) + '):')}")
        for p in likely[:10]:
            print(f"     • {p['platform']}")
    if blocked:
        print(f"\n  {c(C.YELLOW, '⚠️ BLOCKED (' + str(len(blocked)) + '):')}")
        for p in blocked[:10]:
            print(f"     • {p['platform']}: {p['status']}")
    if notfound:
        print(f"\n  {c(C.DIM, '❌ NOT FOUND (' + str(len(notfound)) + '):')}")
        for p in notfound[:10]:
            print(f"     • {p['platform']}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🔎 OSINT TOOLS & QUERIES"))
    print(f"{'─'*70}")
    print(f"  [Google Dorks]:")
    print(f"    1. site:linkedin.com \"{username}\"")
    print(f"    2. site:twitter.com \"{username}\"")
    print(f"    3. \"{username}\" filetype:pdf")
    print(f"    4. intitle:\"index of\" \"{username}\"")
    print(f"\n  [Cached Profiles]:")
    print(f"    • Wayback: https://web.archive.org/web/*/{username}")
    print(f"    • Google Cache: https://webcache.googleusercontent.com/search?q=cache:{username}")
    print()
    print(f"{'='*70}")
    print(c(C.BOLD + C.CYAN, "  📊 SUMMARY"))
    print(f"{'='*70}")
    print(f"  Username: {username}")
    print(f"  GitHub: {'YES' if gh['found'] else 'NO'} | Keybase: {'YES' if kb['found'] else 'NO'}")
    print(f"  Sherlock Found: {len(found)} | Likely: {len(likely)} | Not Found: {len(notfound)}")
    print(f"{'='*70}")
    print(c(C.GREEN + C.BOLD, "  ✅ USERNAME SCAN COMPLETE"))
    print(f"{'='*70}\n")

async def scan_email(s, email):
    domain = email.split('@')[1]
    prefix = email.split('@')[0]
    print(f"\n{'='*70}")
    print(c(C.BOLD + C.CYAN, "  👻 PHANTOMHUNTER v2.2 — Email Reconnaissance"))
    print(c(C.CYAN, f"  Target: {email}"))
    print(c(C.CYAN, f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(f"{'='*70}\n")
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  📡 PHASE 1: Infrastructure & DNS"))
    print(f"{'─'*70}")
    mx, spf, dmarc, ns, a = get_mx(domain), get_spf(domain), get_dmarc(domain), get_ns(domain), get_a(domain)
    print(f"  Domain: {c(C.BOLD, domain)}")
    print(f"  ├─ A: {a if a else 'None'}")
    print(f"  ├─ NS: {ns if ns else 'None'}")
    print(f"  ├─ MX ({len(mx)}): {mx[:5]}{'...' if len(mx) > 5 else ''}")
    print(f"  ├─ SPF: {spf if spf else c(C.RED, '⚠️ None')}")
    print(f"  ├─ DMARC: {dmarc if dmarc else c(C.RED, '⚠️ None')}")
    disp = check_disposable(domain)
    print(f"  ├─ Disposable: {c(C.RED, '🔴 YES') if disp else c(C.GREEN, '🟢 No')}")
    dom_info, ip_info = await asyncio.gather(check_domain_age(s, domain), check_ipinfo(s, domain))
    if dom_info['found']:
        print(f"  ├─ Registrar: {dom_info.get('registrar', '')}")
        print(f"  ├─ Created: {dom_info.get('created', '')}")
        print(f"  ├─ Expires: {dom_info.get('expires', '')}")
    if ip_info['found']:
        print(f"  ├─ IP: {ip_info['ip']}")
        print(f"  ├─ Org: {ip_info.get('org', 'N/A')}")
        print(f"  ├─ Loc: {ip_info.get('city', '')}, {ip_info.get('region', '')}, {ip_info.get('country', '')}")
        print(f"  └─ Coords: {ip_info.get('loc', 'N/A')}")
        ptr = get_ptr(ip_info['ip'])
        if ptr:
            print(f"  └─ PTR: {', '.join(ptr)}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🧬 PHASE 2: Username Intelligence"))
    print(f"{'─'*70}")
    usernames = derive_usernames(email)
    print(f"  Prefix: '{c(C.BOLD, prefix)}' | {len(usernames)} variations:")
    for i, u in enumerate(usernames, 1):
        print(f"    {i:2d}. {u}")
    print(f"\n  Patterns for @{domain}:")
    for p in patterns(domain):
        print(f"    • {p}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  👤 PHASE 3: Profile Discovery"))
    print(f"{'─'*70}")
    gravatar, github, emailrep, hibp_b, hibp_p = await asyncio.gather(
        check_gravatar(s, email), check_github_email(s, email), check_emailrep(s, email),
        check_hibp_breach(s, email), check_hibp_paste(s, email))
    print(f"  [Gravatar] {'✅ ' + gravatar['name'] if gravatar['found'] else '❌ Not found'}")
    if gravatar['found']:
        print(f"     Photo: {gravatar.get('photo', '')}")
        print(f"     Profile: {gravatar.get('profile', '')}")
    print(f"\n  [GitHub Commits] {'✅ ' + str(github.get('commit_count', 0)) + ' commits' if github['found'] else '❌ None'}")
    if github['found']:
        print(f"     Repos: {', '.join(github.get('repos', [])[:5])}")
    elif github.get('error'):
        print(f"     ⚠️ {github['error']}")
    print(f"\n  [EmailRep] {emailrep['reputation'].upper() if emailrep['found'] else '❌ N/A'}")
    if emailrep['found']:
        print(f"     Suspicious: {emailrep['suspicious']} | Blacklisted: {emailrep['blacklisted']} | Spam: {emailrep['spam']}")
        print(f"     Free: {emailrep['free_provider']} | Disposable: {emailrep['disposable']} | DMARC: {emailrep['dmarc_enforced']}")
    print(f"\n  [HIBP Breaches] {'🔴 ' + str(hibp_b['count']) + ' breaches' if hibp_b['found'] else '✅ ' + hibp_b.get('note', 'None')}")
    if hibp_b['found']:
        for b in hibp_b.get('breaches', [])[:10]:
            print(f"     • {b}")
    print(f"\n  [HIBP Pastes] {'🔴 ' + str(hibp_p['pastes']) + ' pastes' if hibp_p['found'] else '✅ ' + hibp_p.get('note', 'None')}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  💻 PHASE 4: GitHub User Profile"))
    print(f"{'─'*70}")
    gh_user = await check_github_user(s, prefix)
    if gh_user['found']:
        print(f"  ✅ {gh_user['login']}")
        print(f"     Name: {gh_user.get('name', '')} | Company: {gh_user.get('company', '')} | Location: {gh_user.get('location', '')}")
        print(f"     Repos: {gh_user['public_repos']} | Followers: {gh_user['followers']} | Created: {gh_user.get('created_at', '')}")
        print(f"     URL: {gh_user['url']}")
    else:
        print(f"  ❌ No exact match for '{prefix}'")
        print(f"  Trying variations...")
        found_alt = False
        for u in usernames[:8]:
            if u != prefix and re.match(r'^[a-zA-Z0-9]+$', u):
                gu = await check_github_user(s, u)
                if gu['found']:
                    print(f"  ✅ Match: {u} -> {gu['login']} | {gu.get('url', '')}")
                    found_alt = True
                    break
        if not found_alt:
            print(f"  ⚠️ No matches")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🌐 PHASE 5: Sherlock Hunt (100+ Sites)"))
    print(f"{'─'*70}")
    tasks = [check_social(s, p, u.replace('{u}', prefix)) for p, u in SITES.items()]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r['status'] == 'found']
    likely = [r for r in results if r['status'] == 'likely_exists']
    notfound = [r for r in results if r['status'] == 'not_found']
    blocked = [r for r in results if r['status'] not in ['found', 'likely_exists', 'not_found']]
    if found:
        print(f"  {c(C.GREEN, '✅ FOUND (' + str(len(found)) + '):')}")
        for p in found[:20]:
            print(f"     • {p['platform']}: {p['url']}")
        if len(found) > 20:
            print(f"     ... and {len(found) - 20} more")
    if likely:
        print(f"\n  {c(C.YELLOW, '🟡 LIKELY (' + str(len(likely)) + '):')}")
        for p in likely[:10]:
            print(f"     • {p['platform']}")
    if blocked:
        print(f"\n  {c(C.YELLOW, '⚠️ BLOCKED (' + str(len(blocked)) + '):')}")
        for p in blocked[:10]:
            print(f"     • {p['platform']}: {p['status']}")
    if notfound:
        print(f"\n  {c(C.DIM, '❌ NOT FOUND (' + str(len(notfound)) + '):')}")
        for p in notfound[:10]:
            print(f"     • {p['platform']}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🗺️ PHASE 6: Subdomain Enumeration"))
    print(f"{'─'*70}")
    dns_subs = await check_subdomains(s, domain)
    crt_subs = await check_crtsh(s, domain)
    all_subs = set(dns_subs)
    if crt_subs['found']:
        all_subs.update(crt_subs['subdomains'])
    if all_subs:
        print(f"  ✅ {len(all_subs)} subdomains:")
        for sub in sorted(list(all_subs))[:30]:
            print(f"     • {sub}")
        if len(all_subs) > 30:
            print(f"     ... and {len(all_subs) - 30} more")
    else:
        print(f"  ⚠️ No subdomains found")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🔎 PHASE 7: Additional Intelligence"))
    print(f"{'─'*70}")
    keybase = await check_keybase(s, prefix)
    print(f"  [Keybase] {'✅ ' + keybase['url'] if keybase['found'] else '❌ Not found'}")
    google = await check_google(s, email)
    if google.get('picasa') or google.get('account_redirect'):
        print(f"  [Google] {'✅ Picasa' if google.get('picasa') else ''} {'✅ Redirect' if google.get('account_redirect') else ''}")
    else:
        print("  [Google] ❌ No indicators")
    pastebin = await check_pastebin(s, email)
    print(f"  [Pastebin] {'🔴 ' + str(pastebin['count']) + ' pastes' if pastebin['found'] else '✅ None'}")
    print()
    print(f"{'─'*70}")
    print(c(C.BOLD + C.YELLOW, "  🛠️ PHASE 8: OSINT Tools & Queries"))
    print(f"{'─'*70}")
    print(f"  [Google Dorks]:")
    for i, d in enumerate(dorks(email, prefix, domain)[:10], 1):
        print(f"    {i}. {d}")
    print(f"\n  [Shodan]:")
    for q in shodan_queries(domain, ip_info.get('ip', '') if ip_info['found'] else '')[:5]:
        print(f"    • https://www.shodan.io/search?query={quote(q)}")
    print(f"\n  [Cached Profiles]:")
    for name, url in cached(prefix, email).items():
        print(f"    • {name}: {url}")
    print(f"\n  [More Tools]:")
    print(f"    • CRT.sh: https://crt.sh/?q={domain}")
    print(f"    • WHOIS: https://whois.domaintools.com/{domain}")
    print(f"    • DNS History: https://securitytrails.com/domain/{domain}/history/a")
    print(f"    • IP History: https://viewdns.info/iphistory/?domain={domain}")
    print()
    print(f"{'='*70}")
    print(c(C.BOLD + C.CYAN, "  📊 SUMMARY"))
    print(f"{'='*70}")
    print(f"  Email: {email} | Domain: {domain}")
    print(f"  MX: {len(mx)} | Disposable: {'YES' if disp else 'No'} | Variations: {len(usernames)}")
    print(f"  Gravatar: {'YES' if gravatar['found'] else 'NO'} | GitHub Commits: {github.get('commit_count', 0) if github['found'] else 0} | GitHub User: {'YES' if gh_user['found'] else 'NO'}")
    print(f"  Reputation: {emailrep.get('reputation', 'N/A') if emailrep['found'] else 'N/A'} | Breaches: {hibp_b.get('count', 0) if hibp_b['found'] else 0} | Pastes: {hibp_p.get('pastes', 0) if hibp_p['found'] else 0}")
    print(f"  Sherlock Found: {len(found)} | Likely: {len(likely)} | Subdomains: {len(all_subs)}")
    print(f"{'='*70}")
    print(c(C.GREEN + C.BOLD, "  ✅ EMAIL SCAN COMPLETE"))
    print(f"{'='*70}\n")

async def main():
    target = None
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target (phone/email/username): ").strip()
    if not target:
        print(c(C.RED, "[ERROR] No target provided."))
        print("Usage: python phantomhunter_v22.py <phone|email|username>")
        return
    target_type = detect_target_type(target)
    conn = aiohttp.TCPConnector(limit=15, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as s:
        if target_type == 'PHONE':
            await scan_phone(s, target)
        elif target_type == 'EMAIL':
            await scan_email(s, target)
        elif target_type == 'USERNAME':
            await scan_username(s, target)
        else:
            print(c(C.RED, f"[ERROR] Could not determine target type for: {target}"))

if __name__ == '__main__':
    asyncio.run(main())
