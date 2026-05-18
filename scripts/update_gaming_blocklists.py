from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = ROOT / "sources.json"

DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:\*\.)?"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63})"
    r"(?![A-Za-z0-9_-])"
)

URL_HOST_RE = re.compile(r"https?://([^/\s'\"<>]+)", re.IGNORECASE)
IPV4_CIDR_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![0-9A-Fa-f:.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![0-9A-Fa-f:])")

COMMON_FALSE_DOMAIN_SUFFIXES = {"example.com", "example.org", "example.net", "test.com", "localhost.localdomain"}
COMMON_NON_GAME_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "api.github.com", "docs.github.com",
    "youtube.com", "youtu.be", "google.com", "gstatic.com", "discord.com",
    "discord.gg", "telegram.org", "t.me", "whatsapp.com", "openwrt.org",
}
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".7z", ".rar",
    ".exe", ".dll", ".bin", ".dat", ".pak", ".mp4", ".mp3", ".wav", ".ttf", ".otf",
}


def log(message: str) -> None:
    print(message, flush=True)


def warn(message: str) -> None:
    print(f"WARNING: {message}", file=sys.stderr, flush=True)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.rstrip("\n\r") for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]


def normalize_existing_key(line: str) -> str:
    return line.strip().lower()


def append_unique(path: Path, new_items: Iterable[str], dry_run: bool = False) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_lines = read_lines(path)
    existing_keys = {normalize_existing_key(x) for x in existing_lines if normalize_existing_key(x)}
    to_add: list[str] = []
    for item in new_items:
        item = item.strip()
        if not item:
            continue
        key = normalize_existing_key(item)
        if key in existing_keys:
            continue
        existing_keys.add(key)
        to_add.append(item)
    if not to_add:
        return 0
    if dry_run:
        log(f"[dry-run] Would append {len(to_add)} line(s) to {path.relative_to(ROOT)}")
        return len(to_add)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        if existing_lines and existing_lines[-1] != "":
            f.write("\n")
        for item in to_add:
            f.write(item + "\n")
    return len(to_add)


def strip_comments(line: str) -> str:
    line = re.sub(r"(?<!:)//.*$", "", line)
    line = line.split("#", 1)[0]
    return line.strip()


def clean_possible_domain(raw: str) -> str | None:
    token = raw.strip().lower()
    token = token.strip("`'\"<>[](){}|,;!")
    token = token.removeprefix("||").removeprefix("*.").removeprefix("address=/").strip("/^")
    if token.startswith(("http://", "https://")):
        token = urllib.parse.urlsplit(token).netloc
    if "@" in token:
        return None
    token = token.split("/", 1)[0].split(":", 1)[0].strip(".")
    if not token or token in COMMON_FALSE_DOMAIN_SUFFIXES or token in COMMON_NON_GAME_DOMAINS:
        return None
    if "_" in token or len(token) > 253:
        return None
    labels = token.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return None
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None
    if not re.fullmatch(r"[a-z]{2,63}", labels[-1]):
        return None
    if token.endswith((".md", ".txt", ".bat", ".cmd", ".json", ".yaml", ".yml", ".png", ".jpg")):
        return None
    return token


def normalize_ip(raw: str) -> str | None:
    token = raw.strip().strip("`'\"<>[](){}|,;!")
    if not token:
        return None
    try:
        if "/" in token:
            return str(ipaddress.ip_network(token, strict=False))
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def extract_domains(text: str) -> set[str]:
    found: set[str] = set()
    for match in URL_HOST_RE.finditer(text):
        domain = clean_possible_domain(match.group(1))
        if domain:
            found.add(domain)
    for match in DOMAIN_RE.finditer(text):
        domain = clean_possible_domain(match.group(1))
        if domain:
            found.add(domain)
    for match in re.finditer(r"address=/([^/\s]+)/", text, re.IGNORECASE):
        domain = clean_possible_domain(match.group(1))
        if domain:
            found.add(domain)
    return found


def extract_ips(text: str) -> set[str]:
    found: set[str] = set()
    for match in IPV4_CIDR_RE.finditer(text):
        value = normalize_ip(match.group(0))
        if value:
            found.add(value)
    for match in IPV6_CANDIDATE_RE.finditer(text):
        value = normalize_ip(match.group(0))
        if value:
            found.add(value)
    return found


def normalize_text_for_match(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    return text.replace("_", " ").replace("-", " ").replace("/", " ")


def slugify_game_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9А-Яа-яЁё]+", "_", name.strip()).strip("_")
    return (cleaned or "Other_Games") + ".txt"


def build_alias_index(game_map: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    index: list[tuple[str, str, str]] = []
    for game, aliases in game_map.items():
        for alias in [game] + aliases:
            norm = normalize_text_for_match(alias)
            if norm:
                index.append((game, alias, norm))
    index.sort(key=lambda x: len(x[2]), reverse=True)
    return index


def infer_games_from_context(context: str, alias_index: list[tuple[str, str, str]], domain_game_hints: dict[str, list[str]] | None = None) -> set[str]:
    games: set[str] = set()
    norm_context = normalize_text_for_match(context)
    for game, _alias, norm_alias in alias_index:
        if len(norm_alias) <= 3:
            if re.search(rf"(?<![a-zа-я0-9]){re.escape(norm_alias)}(?![a-zа-я0-9])", norm_context):
                games.add(game)
        elif norm_alias in norm_context:
            games.add(game)
    if domain_game_hints:
        lower_context = context.lower()
        for game, hints in domain_game_hints.items():
            if any(hint.lower() in lower_context for hint in hints):
                games.add(game)
    return games


def sanitize_explicit_game_name(name: str) -> str | None:
    name = re.sub(r"\s+", " ", name.strip().strip("`'\"[](){}")).strip(" .,:;/-_|")
    if not name or len(name) < 2 or len(name) > 60:
        return None
    bad = normalize_text_for_match(name)
    generic = {"hostlist", "ipset", "список доменов", "список ip", "no response", "none", "описание", "description", "последняя", "latest", "general", "game filter", "ipset filter"}
    if bad in generic or re.fullmatch(r"[0-9. /:-]+", name):
        return None
    parts = [p for p in re.split(r"[^A-Za-z0-9А-Яа-яЁё]+", name) if p]
    if not parts:
        return None
    return "_".join(part[:1].upper() + part[1:] for part in parts)


def infer_explicit_games_from_text(text: str, alias_index: list[tuple[str, str, str]], domain_game_hints: dict[str, list[str]]) -> set[str]:
    games: set[str] = set()
    sample = text[:4000]
    patterns = [
        r"\[(?:hostlist|ipset|game|service|сервис|игра)\]\s*:?\s*([^#\n\r]{2,60})",
        r"(?:название\s+(?:сервиса|сайта|игры)|service\s+name|game\s+name)\s*(?:/\s*сайта)?\s*[:\n\r]+\s*([^\n\r]{2,60})",
        r"(?:для|for)\s+([A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9 ._+&/-]{2,50})",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, sample, flags=re.IGNORECASE):
            raw_name = re.split(r"[#|<>{}\[\]\n\r]", match.group(1), 1)[0]
            canonical = infer_games_from_context(raw_name, alias_index, domain_game_hints)
            if canonical:
                games.update(canonical)
            else:
                sanitized = sanitize_explicit_game_name(raw_name)
                if sanitized:
                    games.add(sanitized)
    return games


def resolve_game_file(games_dir: Path, game: str) -> Path:
    preferred = games_dir / f"{game}.txt"
    if preferred.exists():
        return preferred
    game_norm = re.sub(r"[^a-z0-9]+", "", game.lower())
    candidates: list[Path] = []
    for path in games_dir.glob("*.txt"):
        stem_norm = re.sub(r"[^a-z0-9]+", "", path.stem.lower())
        if stem_norm == game_norm or game_norm in stem_norm or stem_norm in game_norm:
            candidates.append(path)
    if candidates:
        candidates.sort(key=lambda p: len(p.name))
        return candidates[0]
    return games_dir / slugify_game_name(game)


@dataclasses.dataclass
class Harvested:
    domains_global: OrderedDict[str, None] = dataclasses.field(default_factory=OrderedDict)
    ips_global: OrderedDict[str, None] = dataclasses.field(default_factory=OrderedDict)
    domains_by_game: dict[str, OrderedDict[str, None]] = dataclasses.field(default_factory=lambda: defaultdict(OrderedDict))
    ips_by_game: dict[str, OrderedDict[str, None]] = dataclasses.field(default_factory=lambda: defaultdict(OrderedDict))
    sources_scanned: int = 0

    def add_domain(self, domain: str, games: Iterable[str]) -> None:
        self.domains_global[domain] = None
        for game in games:
            self.domains_by_game[game][domain] = None

    def add_ip(self, ip_or_cidr: str, games: Iterable[str]) -> None:
        self.ips_global[ip_or_cidr] = None
        for game in games:
            self.ips_by_game[game][ip_or_cidr] = None


class GitHubClient:
    def __init__(self, token: str | None, timeout: int = 35, sleep_seconds: float = 0.35):
        self.token = token
        self.timeout = timeout
        self.sleep_seconds = sleep_seconds
        self.api_base = "https://api.github.com"
        self.last_request_at = 0.0

    def _headers(self, raw: bool = False) -> dict[str, str]:
        headers = {"User-Agent": "medvedeff-ru-gaming-blocklist-updater", "Accept": "application/vnd.github+json" if not raw else "text/plain, */*", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _sleep_if_needed(self) -> None:
        elapsed = time.time() - self.last_request_at
        if elapsed < self.sleep_seconds:
            time.sleep(self.sleep_seconds - elapsed)

    def get_json(self, path_or_url: str, params: dict[str, Any] | None = None) -> Any:
        url = path_or_url if path_or_url.startswith("http") else self.api_base + path_or_url
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        self._sleep_if_needed()
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self.last_request_at = time.time()
                payload = resp.read().decode("utf-8", errors="replace")
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:500]
            if e.code in {403, 429}:
                warn(f"GitHub API rate/permission response for {url}: HTTP {e.code}: {body}")
                time.sleep(10)
                return None
            warn(f"GitHub API error for {url}: HTTP {e.code}: {body}")
            return None
        except Exception as e:
            warn(f"GitHub API error for {url}: {e}")
            return None

    def get_text(self, url: str) -> str | None:
        self._sleep_if_needed()
        req = urllib.request.Request(url, headers=self._headers(raw=True))
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self.last_request_at = time.time()
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            warn(f"HTTP error for {url}: {e.code}")
            return None
        except Exception as e:
            warn(f"HTTP error for {url}: {e}")
            return None

    def search_issues(self, repo: str, term: str, max_pages: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        query = f"repo:{repo} is:issue {term}"
        for page in range(1, max_pages + 1):
            data = self.get_json("/search/issues", {"q": query, "sort": "updated", "order": "desc", "per_page": 100, "page": page})
            if not data or not isinstance(data, dict):
                break
            batch = data.get("items") or []
            for item in batch:
                if "pull_request" not in item:
                    items.append(item)
            if len(batch) < 100:
                break
        return items

    def issue_comments(self, repo: str, number: int, max_comments: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        pages = max(1, (max_comments + 99) // 100)
        for page in range(1, pages + 1):
            data = self.get_json(f"/repos/{repo}/issues/{number}/comments", {"per_page": min(100, max_comments), "page": page})
            if not isinstance(data, list):
                break
            comments.extend(data)
            if len(data) < 100 or len(comments) >= max_comments:
                break
        return comments[:max_comments]

    def repo_info(self, repo: str) -> dict[str, Any] | None:
        data = self.get_json(f"/repos/{repo}")
        return data if isinstance(data, dict) else None

    def repo_tree(self, repo: str, branch: str) -> list[dict[str, Any]]:
        data = self.get_json(f"/repos/{repo}/git/trees/{urllib.parse.quote(branch, safe='')}", {"recursive": "1"})
        if isinstance(data, dict) and isinstance(data.get("tree"), list):
            return data["tree"]
        return []

    def search_repositories(self, query: str, max_results: int) -> list[dict[str, Any]]:
        data = self.get_json("/search/repositories", {"q": query, "sort": "updated", "order": "desc", "per_page": max_results})
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return data["items"]
        return []


def source_options(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "trust_all_domains_as_gaming": bool(source.get("trust_all_domains_as_gaming", False)),
        "default_game": source.get("default_game"),
        "kind": source.get("kind", "mixed"),
        "allow_issue_file_fallback": bool(source.get("allow_issue_file_fallback", False)),
    }


def process_text(harvested: Harvested, text: str, source_context: str, alias_index: list[tuple[str, str, str]], domain_game_hints: dict[str, list[str]], options: dict[str, Any]) -> None:
    trust_all = bool(options.get("trust_all_domains_as_gaming"))
    default_game = options.get("default_game")
    kind = options.get("kind", "mixed")
    base_games = infer_explicit_games_from_text(source_context + "\n" + text, alias_index, domain_game_hints)

    for raw_line in text.splitlines():
        line = strip_comments(raw_line)
        if not line:
            continue

        context = f"{source_context}\n{line}"
        games = set(base_games) | infer_games_from_context(context, alias_index, domain_game_hints)
        games = {
            game for game in games
            if normalize_text_for_match(game).replace(" ", "_") not in BLOCKED_GAME_NAMES
        }

        issue_fallback_games: set[str] = set()
        if not games and bool(options.get("allow_issue_file_fallback")):
            fallback_name = issue_fallback_game_name(source_context)
            if fallback_name:
                issue_fallback_games.add(fallback_name)

        if trust_all and default_game:
            games.add(str(default_game))

        if kind in {"mixed", "domains"}:
            for domain in extract_domains(line):
                domain_games = set(games) | infer_games_from_context(domain, alias_index, domain_game_hints)
                domain_games = {
                    game for game in domain_games
                    if normalize_text_for_match(game).replace(" ", "_") not in BLOCKED_GAME_NAMES
                }
                if trust_all and default_game:
                    domain_games.add(str(default_game))
                if not domain_games and issue_fallback_games:
                    domain_games.update(issue_fallback_games)
                if domain_games:
                    harvested.add_domain(domain, sorted(domain_games))

        if kind in {"mixed", "ips"}:
            for ip_or_cidr in extract_ips(line):
                ip_games = set(games)
                if trust_all and default_game:
                    ip_games.add(str(default_game))
                if not ip_games and issue_fallback_games:
                    ip_games.update(issue_fallback_games)
                if ip_games:
                    harvested.add_ip(ip_or_cidr, sorted(ip_games))


def score_repository_for_discovery(repo_item: dict[str, Any]) -> int:
    text = normalize_text_for_match(" ".join([repo_item.get("full_name") or "", repo_item.get("description") or "", " ".join(repo_item.get("topics") or [])]))
    score = 0
    for word in ["zapret", "hostlist", "ipset", "domainlist", "iplist", "blocklist", "gaming", "game"]:
        if word in text:
            score += 2
    for word in ["roblox", "fortnite", "epic", "vrchat", "steam", "valorant", "riot", "minecraft"]:
        if word in text:
            score += 2
    if repo_item.get("stargazers_count", 0) >= 5:
        score += 1
    if repo_item.get("archived"):
        score -= 3
    if repo_item.get("fork"):
        score -= 1
    return score


def discover_repositories(config: dict[str, Any], gh: GitHubClient) -> list[dict[str, Any]]:
    discovery = config.get("repository_discovery") or {}
    if not discovery.get("enabled"):
        return []
    ignore = {x.lower() for x in discovery.get("ignore_repositories", [])}
    known = {x.get("repo", "").lower() for x in config.get("repositories", [])}
    max_per_query = int(config.get("limits", {}).get("max_discovered_repositories_per_query", 4))
    min_score = int(discovery.get("min_score", 4))
    found: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for query in discovery.get("queries", []):
        log(f"Discover repositories: {query}")
        for item in gh.search_repositories(query, max_per_query):
            full_name = item.get("full_name")
            if not full_name:
                continue
            key = full_name.lower()
            if key in ignore or key in known or key in found:
                continue
            score = score_repository_for_discovery(item)
            if score < min_score:
                continue
            found[key] = {"repo": full_name, "scan_issues": bool(discovery.get("scan_issues", True)), "scan_issue_comments": True, "scan_raw_files": bool(discovery.get("scan_raw_files", True)), "max_issue_pages_per_query": 1, "max_comments_per_issue": 20, "allow_issue_file_fallback": True, "discovered": True}
            log(f"  discovered {full_name} (score {score})")
    return list(found.values())


def should_scan_path(path: str, tree_item: dict[str, Any], config: dict[str, Any]) -> bool:
    path_lower = path.lower()
    ext = Path(path_lower).suffix
    if ext in BINARY_EXTENSIONS:
        return False
    filters = config.get("raw_file_filters") or {}
    allowed_extensions = set(filters.get("extensions") or [])
    if allowed_extensions and ext and ext not in allowed_extensions:
        return False
    size = tree_item.get("size")
    max_size = int(config.get("limits", {}).get("max_raw_file_size_bytes", 450000))
    if isinstance(size, int) and size > max_size:
        return False
    keywords = [x.lower() for x in filters.get("path_keywords", [])]
    return True if not keywords else any(keyword in path_lower for keyword in keywords)


def raw_url_for(repo: str, branch: str, path: str) -> str:
    encoded_path = "/".join(urllib.parse.quote(part) for part in path.split("/"))
    return f"https://raw.githubusercontent.com/{repo}/{urllib.parse.quote(branch, safe='')}/{encoded_path}"


def scan_raw_files_from_repo(harvested: Harvested, repo_cfg: dict[str, Any], config: dict[str, Any], gh: GitHubClient, alias_index: list[tuple[str, str, str]], domain_game_hints: dict[str, list[str]]) -> None:
    repo = repo_cfg["repo"]
    info = gh.repo_info(repo)
    if not info:
        return
    branch = repo_cfg.get("branch") or info.get("default_branch") or "main"
    tree = gh.repo_tree(repo, branch)
    if not tree:
        return
    max_files = int(repo_cfg.get("max_raw_files_per_repo") or config.get("limits", {}).get("max_raw_files_per_repo", 80))
    options = source_options(repo_cfg)
    selected = [item for item in tree if item.get("type") == "blob" and item.get("path") and should_scan_path(item.get("path") or "", item, config)][:max_files]
    log(f"Repo raw scan {repo}: {len(selected)} file(s)")
    for item in selected:
        path = item.get("path") or ""
        text = gh.get_text(raw_url_for(repo, branch, path))
        if text is None:
            continue
        process_text(harvested, text, f"repo:{repo} path:{path}", alias_index, domain_game_hints, options)
        harvested.sources_scanned += 1


def scan_issues_from_repo(harvested: Harvested, repo_cfg: dict[str, Any], config: dict[str, Any], gh: GitHubClient, alias_index: list[tuple[str, str, str]], domain_game_hints: dict[str, list[str]]) -> None:
    repo = repo_cfg["repo"]
    terms = repo_cfg.get("issue_search_terms") or config.get("issue_search_terms") or []
    max_pages = int(repo_cfg.get("max_issue_pages_per_query") or config.get("limits", {}).get("max_issue_pages_per_query", 2))
    max_comments = int(repo_cfg.get("max_comments_per_issue") or config.get("limits", {}).get("max_comments_per_issue", 40))
    scan_comments = bool(repo_cfg.get("scan_issue_comments", True))
    options = source_options(repo_cfg)
    seen_issue_numbers: set[int] = set()
    log(f"Repo issue scan {repo}: {len(terms)} term(s), max {max_pages} page(s) per term")
    for term in terms:
        for issue in gh.search_issues(repo, term, max_pages=max_pages):
            number = issue.get("number")
            if not isinstance(number, int) or number in seen_issue_numbers:
                continue
            seen_issue_numbers.add(number)
            title, body, url = issue.get("title") or "", issue.get("body") or "", issue.get("html_url") or ""
            issue_context = f"repo:{repo} issue:#{number} {title} {url}"
            process_text(harvested, f"{title}\n{body}", issue_context, alias_index, domain_game_hints, options)
            harvested.sources_scanned += 1
            if scan_comments and max_comments > 0:
                for comment in gh.issue_comments(repo, number, max_comments=max_comments):
                    process_text(harvested, comment.get("body") or "", issue_context, alias_index, domain_game_hints, options)
                    harvested.sources_scanned += 1


def scan_raw_sources(harvested: Harvested, config: dict[str, Any], gh: GitHubClient, alias_index: list[tuple[str, str, str]], domain_game_hints: dict[str, list[str]]) -> None:
    for source in config.get("raw_sources", []):
        name, url = source.get("name") or source.get("url"), source.get("url")
        if not url:
            continue
        log(f"Raw source: {name}")
        text = gh.get_text(url)
        if text is None:
            continue
        process_text(harvested, text, f"raw:{name} {url}", alias_index, domain_game_hints, source_options(source))
        harvested.sources_scanned += 1


def write_results(harvested: Harvested, config: dict[str, Any], dry_run: bool) -> None:
    output = config.get("output") or {}
    domains_file = ROOT / output.get("domains_file", "medvedeff-game-list-all.txt")
    ips_file = ROOT / output.get("ips_file", "medvedeff-game-ipset.txt")
    games_dir = ROOT / output.get("games_dir", "games")
    write_ips_to_game_files = bool(output.get("write_ips_to_game_files", True))
    domains, ips = list(harvested.domains_global.keys()), list(harvested.ips_global.keys())
    log(f"Collected candidates: {len(domains)} domain(s), {len(ips)} IP/CIDR item(s)")
    added_domains = append_unique(domains_file, domains, dry_run=dry_run)
    added_ips = append_unique(ips_file, ips, dry_run=dry_run)
    log(f"Global files: +{added_domains} domain(s), +{added_ips} IP/CIDR item(s)")
    total_game_added = 0
    for game, items in sorted(harvested.domains_by_game.items()):
        path = resolve_game_file(games_dir, game)
        count = append_unique(path, items.keys(), dry_run=dry_run)
        if count:
            log(f"Game file {path.relative_to(ROOT)}: +{count} domain(s)")
            total_game_added += count
    if write_ips_to_game_files:
        for game, items in sorted(harvested.ips_by_game.items()):
            path = resolve_game_file(games_dir, game)
            count = append_unique(path, items.keys(), dry_run=dry_run)
            if count:
                log(f"Game file {path.relative_to(ROOT)}: +{count} IP/CIDR item(s)")
                total_game_added += count
    log(f"Game breakdown: +{total_game_added} line(s)")


def apply_run_mode(config: dict[str, Any], mode: str) -> None:
    limits = config.setdefault("limits", {})
    if mode == "fast":
        log("Fast scan mode: 3-hour lightweight scan")
        limits["max_issue_pages_per_query"] = 1
        limits["max_comments_per_issue"] = 0
        limits["max_raw_files_per_repo"] = min(40, int(limits.get("max_raw_files_per_repo", 40)))
        config.setdefault("repository_discovery", {})["enabled"] = False
        for repo_cfg in config.get("repositories", []):
            repo_cfg["scan_issue_comments"] = False
            repo_cfg["allow_issue_file_fallback"] = False
            repo_cfg["max_issue_pages_per_query"] = 1
            repo_cfg["max_comments_per_issue"] = 0
            repo_cfg["max_raw_files_per_repo"] = min(40, int(repo_cfg.get("max_raw_files_per_repo", 40)))
    elif mode == "full":
        log("Full scan mode: deep historical scan")
        limits["max_issue_pages_per_query"] = max(10, int(limits.get("max_issue_pages_per_query", 2)))
        limits["max_comments_per_issue"] = max(80, int(limits.get("max_comments_per_issue", 40)))
        limits["max_raw_files_per_repo"] = max(120, int(limits.get("max_raw_files_per_repo", 80)))
        discovery = config.setdefault("repository_discovery", {})
        if discovery.get("queries"):
            discovery["enabled"] = True
        for repo_cfg in config.get("repositories", []):
            repo_cfg["scan_issue_comments"] = True
            repo_cfg["allow_issue_file_fallback"] = True
            repo_cfg["max_issue_pages_per_query"] = max(10, int(repo_cfg.get("max_issue_pages_per_query", 2)))
            repo_cfg["max_comments_per_issue"] = max(80, int(repo_cfg.get("max_comments_per_issue", 40)))
            repo_cfg["max_raw_files_per_repo"] = max(120, int(repo_cfg.get("max_raw_files_per_repo", 80)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to sources.json")
    parser.add_argument("--dry-run", action="store_true", help="Collect and print stats but do not write files")
    parser.add_argument("--mode", choices=["fast", "full"], default=None, help="Run mode: fast for regular 3-hour scan, full for deep scan")
    parser.add_argument("--full-scan", action="store_true", help="Legacy option. Same as --mode full")
    args = parser.parse_args()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    config = load_json(config_path)
    mode = args.mode or ("full" if args.full_scan else "fast")
    apply_run_mode(config, mode)
    limits = config.get("limits") or {}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        warn("GITHUB_TOKEN/GH_TOKEN is not set. Public GitHub API rate limit will be much lower.")
    gh = GitHubClient(token=token, timeout=int(limits.get("http_timeout_seconds", 35)), sleep_seconds=float(limits.get("sleep_between_github_requests_seconds", 0.35)))
    game_map = config.get("game_map") or {}
    domain_game_hints = config.get("domain_game_hints") or {}
    alias_index = build_alias_index(game_map)
    harvested = Harvested()
    repositories = list(config.get("repositories") or [])
    repositories.extend(discover_repositories(config, gh))
    scan_raw_sources(harvested, config, gh, alias_index, domain_game_hints)
    for repo_cfg in repositories:
        repo = repo_cfg.get("repo")
        if not repo:
            continue
        log(f"--- Scanning repository {repo} ---")
        if repo_cfg.get("scan_issues", True):
            scan_issues_from_repo(harvested, repo_cfg, config, gh, alias_index, domain_game_hints)
        if repo_cfg.get("scan_raw_files", True):
            scan_raw_files_from_repo(harvested, repo_cfg, config, gh, alias_index, domain_game_hints)
    log(f"Sources/text blocks scanned: {harvested.sources_scanned}")
    write_results(harvested, config, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
