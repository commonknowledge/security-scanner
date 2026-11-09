<?php
/**
 * CK Health. Loaded by ../ck-health.php on PHP 7.2+.
 *
 * 1. Status endpoint: GET /wp-json/ck-health/v1/status (or ?rest_route=/ck-health/v1/status).
 *    Answers only requests signed with the scanner's private key; everyone else gets a 404.
 * 2. Password audit: tests each account that can edit content against a list of easily
 *    guessed passwords, using the stored hash. Runs in short time-boxed batches (hourly
 *    via WP-Cron, and on each status request). Never stores or reports a password.
 * 3. Login rate limiting: after 10 failed logins from one visitor IP within 15 minutes,
 *    further attempts from that IP are refused until the 15 minutes are up.
 */

namespace CommonKnowledge\Health;

if (!defined('ABSPATH')) {
	exit;
}

const VERSION = '0.1.0';

/** The scanner's Ed25519 public key. The private key is held only by the scanner. */
const SCANNER_PUBLIC_KEY = 'qjpe29WNhEWuSdL89zQbCVyamdSKwEWEVyQO+Yy1/gk=';
const SIGNED_MESSAGE_PREFIX = "ck-health-v1\n";
const MAX_CLOCK_SKEW = 300;

const LOGIN_FAILURE_LIMIT = 10;
const LOGIN_WINDOW = 900;
const LOCKED_OUT_CODE = 'ck_health_locked_out';
const LOCKOUTS_OPTION = 'ck_health_lockouts';

const AUDIT_CRON_HOOK = 'ck_health_password_audit';
const AUDIT_CRON_BUDGET = 20.0;
const AUDIT_REQUEST_BUDGET = 5.0;
const AUDIT_META = 'ck_health_password_audit';

/** https://www.cloudflare.com/ips/ (fetched 2026-11-09) */
const CLOUDFLARE_RANGES = [
	'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
	'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
	'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
	'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
	'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
	'2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

/** Addresses that can only belong to a hosting provider's own network, never a visitor. */
const PRIVATE_RANGES = [
	'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
	'100.64.0.0/10', '169.254.0.0/16',
	'::1/128', 'fc00::/7', 'fe80::/10',
];

/** Passwords tried against every account, after ones derived from the account and site. */
const COMMON_PASSWORDS = [
	'password', 'Password', 'password1', 'Password1', 'password123', 'Password123',
	'Password1!', 'Password123!', 'passw0rd', 'P@ssw0rd', 'P@ssword', 'p@ssword',
	'123456', '1234567', '12345678', '123456789', '1234567890', '12345', '1234',
	'111111', '000000', '123123', '654321', '666666', '121212', '112233', '123321',
	'qwerty', 'qwerty123', 'qwertyuiop', 'Qwerty123', 'qwerty1', '1q2w3e4r', '1qaz2wsx',
	'zaq12wsx', 'asdfgh', 'asdfghjkl', 'zxcvbnm', 'abc123', 'abcd1234', 'aa123456',
	'admin', 'Admin', 'admin1', 'admin123', 'Admin123', 'admin1234', 'administrator',
	'root', 'toor', 'pass', 'pass123', 'test', 'test123', 'testing', 'guest', 'demo',
	'changeme', 'default', 'secret', 'welcome', 'Welcome1', 'welcome123', 'letmein',
	'login', 'master', 'hello', 'hello123', 'iloveyou', 'monkey', 'dragon', 'sunshine',
	'princess', 'football', 'baseball', 'shadow', 'superman', 'trustno1', 'whatever',
	'starwars', 'freedom', 'michael', 'charlie', 'jordan', 'summer', 'winter',
	'wordpress', 'WordPress', 'wordpress1', 'wordpress123', 'wp-admin', 'wpadmin',
	'website', 'website1', 'website123', 'editor', 'editor123', 'staging', 'staging123',
	'commonknowledge', 'CommonKnowledge', 'commonknowledge1', 'commonknowledge123',
	'solidarity', 'Solidarity1', 'solidarity123', 'organise', 'organize', 'union', 'union123',
];

// ---------------------------------------------------------------------------
// Visitor IP
// ---------------------------------------------------------------------------

function normalise_ip($value): ?string {
	if (!is_string($value)) {
		return null;
	}
	$ip = trim($value);
	if (preg_match('/^\[([0-9a-fA-F:.]+)\](?::\d+)?$/', $ip, $m)) {
		$ip = $m[1]; // [IPv6]:port
	} elseif (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $ip, $m)) {
		$ip = $m[1]; // IPv4:port
	}
	if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
		return null;
	}
	$bin = inet_pton($ip);
	if (strlen($bin) === 16 && substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
		$bin = substr($bin, 12); // IPv4-mapped IPv6
	}
	return inet_ntop($bin);
}

function in_ranges(string $ip, array $ranges): bool {
	$bin = inet_pton($ip);
	foreach ($ranges as $range) {
		list($net, $bits) = explode('/', $range);
		$net = inet_pton($net);
		if (strlen($net) !== strlen($bin)) {
			continue;
		}
		$bits = (int) $bits;
		$bytes = intdiv($bits, 8);
		if (substr($bin, 0, $bytes) !== substr($net, 0, $bytes)) {
			continue;
		}
		$rest = $bits % 8;
		if ($rest === 0) {
			return true;
		}
		$mask = (0xff << (8 - $rest)) & 0xff;
		if ((ord($bin[$bytes]) & $mask) === (ord($net[$bytes]) & $mask)) {
			return true;
		}
	}
	return false;
}

/**
 * Work out the visitor's IP without trusting anything the visitor could forge.
 *
 * REMOTE_ADDR (the machine that actually connected) is the only value a visitor can't
 * fake. Forwarding headers are read only when REMOTE_ADDR shows a proxy:
 * - a Cloudflare address: Cloudflare sets CF-Connecting-IP, overwriting anything sent.
 * - a private address (the host's own load balancer): X-Forwarded-For is read right to
 *   left, skipping the host's own and Cloudflare's hops. Proxies append on the right,
 *   so values a visitor sent sit further left and are never reached.
 * Otherwise it's a direct connection, and REMOTE_ADDR is the visitor.
 *
 * Returns ip => null when the visitor can't be identified safely. Rate limiting is then
 * skipped, so one shared counter can't lock everyone out.
 */
function resolve_visitor_ip(array $server): array {
	$remote = normalise_ip($server['REMOTE_ADDR'] ?? null);
	$cf_header = normalise_ip($server['HTTP_CF_CONNECTING_IP'] ?? null);
	$ip = null;
	$via = 'unresolved';

	if ($remote === null) {
		// Nothing to go on.
	} elseif (in_ranges($remote, CLOUDFLARE_RANGES)) {
		list($ip, $via) = [$cf_header, 'cloudflare'];
	} elseif (!in_ranges($remote, PRIVATE_RANGES)) {
		list($ip, $via) = [$remote, 'direct'];
	} else {
		$hops = array_reverse(explode(',', (string) ($server['HTTP_X_FORWARDED_FOR'] ?? '')));
		foreach ($hops as $hop) {
			$hop_ip = normalise_ip($hop);
			if ($hop_ip === null) {
				break; // Unreadable hop: nothing further left can be trusted.
			}
			if (in_ranges($hop_ip, PRIVATE_RANGES)) {
				continue;
			}
			if (in_ranges($hop_ip, CLOUDFLARE_RANGES)) {
				list($ip, $via) = [$cf_header, 'proxy+cloudflare'];
			} else {
				list($ip, $via) = [$hop_ip, 'proxy'];
			}
			break;
		}
	}

	if ($ip === null || in_ranges($ip, PRIVATE_RANGES) || in_ranges($ip, CLOUDFLARE_RANGES)) {
		list($ip, $via) = [null, 'unresolved'];
	}
	return ['ip' => $ip, 'via' => $via, 'remote_addr' => $remote];
}

// ---------------------------------------------------------------------------
// Login rate limiting
// ---------------------------------------------------------------------------

function login_limit_key(): ?string {
	$visitor = resolve_visitor_ip($_SERVER);
	return $visitor['ip'] === null ? null : 'ck_health_login_' . md5($visitor['ip']);
}

/** Runs after WordPress has checked the password, so this refusal can't be overridden. */
function refuse_locked_out($user, $username, $password) {
	if (empty($username) && empty($password)) {
		return $user; // Login form being displayed, not submitted.
	}
	$key = login_limit_key();
	$state = $key ? get_transient($key) : false;
	if (!is_array($state) || $state['count'] < LOGIN_FAILURE_LIMIT) {
		return $user;
	}
	$minutes = max(1, (int) ceil(($state['expires'] - time()) / 60));
	return new \WP_Error(
		LOCKED_OUT_CODE,
		sprintf('<strong>Error:</strong> Too many failed login attempts. Please try again in %d minute%s.', $minutes, $minutes === 1 ? '' : 's')
	);
}

function count_failed_login($username, $error = null): void {
	if ($error instanceof \WP_Error && $error->get_error_code() === LOCKED_OUT_CODE) {
		return; // Attempts while locked out don't extend the lockout.
	}
	$key = login_limit_key();
	if (!$key) {
		return;
	}
	$now = time();
	$state = get_transient($key);
	if (!is_array($state) || $state['expires'] <= $now) {
		$state = ['count' => 0, 'expires' => $now + LOGIN_WINDOW];
	}
	$state['count']++;
	if ($state['count'] === LOGIN_FAILURE_LIMIT) {
		record_lockout();
	}
	set_transient($key, $state, max(1, $state['expires'] - $now));
}

function record_lockout(): void {
	$log = get_option(LOCKOUTS_OPTION, []);
	$log = is_array($log) ? $log : [];
	$today = gmdate('Y-m-d');
	$log[$today] = ($log[$today] ?? 0) + 1;
	krsort($log);
	update_option(LOCKOUTS_OPTION, array_slice($log, 0, 7, true), false);
}

add_filter('authenticate', __NAMESPACE__ . '\\refuse_locked_out', 99, 3);
add_action('wp_login_failed', __NAMESPACE__ . '\\count_failed_login', 10, 2);

// ---------------------------------------------------------------------------
// Password audit
// ---------------------------------------------------------------------------

function audited_users(): array {
	return get_users(['capability' => 'edit_posts', 'orderby' => 'ID', 'order' => 'ASC']);
}

/** Passwords derived from the account and the site, then the common list. */
function candidate_passwords(\WP_User $user): array {
	$host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
	$host_labels = explode('.', preg_replace('/^www\./', '', strtolower($host)));
	$words = [
		$user->user_login,
		$user->user_nicename,
		$user->display_name,
		$user->first_name,
		$user->last_name,
		strtok((string) $user->user_email, '@'),
		get_bloginfo('name'),
		$host_labels[0] ?? '',
	];

	$year = (int) gmdate('Y');
	$suffixes = ['', '1', '12', '123', '1234', '!', '1!', '123!', '@123', (string) $year, (string) ($year - 1)];
	$candidates = [];
	foreach ($words as $word) {
		$word = preg_replace('/\s+/', '', strtolower((string) $word));
		if (strlen($word) < 3) {
			continue;
		}
		foreach ([$word, ucfirst($word)] as $base) {
			foreach ($suffixes as $suffix) {
				$candidates[] = $base . $suffix;
			}
		}
	}
	return array_values(array_unique(array_merge($candidates, COMMON_PASSWORDS)));
}

/**
 * Where the audit has got to for this user. The fingerprint covers the stored hash and
 * the candidate list, so a password change or a new plugin version starts a fresh audit.
 */
function audit_state(\WP_User $user, array $candidates): array {
	$fingerprint = hash('sha256', $user->user_pass . "\n" . implode("\n", $candidates));
	$saved = get_user_meta($user->ID, AUDIT_META, true);
	if (is_array($saved) && ($saved['fingerprint'] ?? null) === $fingerprint) {
		return $saved;
	}
	return ['fingerprint' => $fingerprint, 'next' => 0, 'done' => false, 'weak' => false];
}

function audit_passwords(float $budget): void {
	$deadline = microtime(true) + $budget;
	foreach (audited_users() as $user) {
		$candidates = candidate_passwords($user);
		$state = audit_state($user, $candidates);
		if ($state['done']) {
			continue;
		}
		$total = count($candidates);
		while ($state['next'] < $total) {
			if (microtime(true) >= $deadline) {
				update_user_meta($user->ID, AUDIT_META, $state);
				return;
			}
			// No user ID passed, so WordPress never rehashes or changes the account.
			if (wp_check_password($candidates[$state['next']], $user->user_pass)) {
				$state['weak'] = true;
				break;
			}
			$state['next']++;
		}
		$state['done'] = true;
		$state['checked'] = time();
		update_user_meta($user->ID, AUDIT_META, $state);
	}
}

function password_audit_summary(): array {
	$summary = ['accounts' => 0, 'pending' => 0, 'weak' => []];
	foreach (audited_users() as $user) {
		$state = audit_state($user, candidate_passwords($user));
		$summary['accounts']++;
		if (!$state['done']) {
			$summary['pending']++;
		} elseif ($state['weak']) {
			$summary['weak'][] = $user->user_login;
		}
	}
	return $summary;
}

add_action(AUDIT_CRON_HOOK, function () {
	audit_passwords(AUDIT_CRON_BUDGET);
});
add_action('init', function () {
	if (!wp_next_scheduled(AUDIT_CRON_HOOK)) {
		wp_schedule_event(time(), 'hourly', AUDIT_CRON_HOOK);
	}
});

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

function wordpress_status(): array {
	global $wp_version;
	$updates = get_site_transient('update_core');
	$available = null;
	foreach ((is_object($updates) && isset($updates->updates)) ? $updates->updates : [] as $offer) {
		if (($offer->response ?? null) === 'upgrade') {
			$available = $offer->current ?? null;
			break;
		}
	}
	return [
		'version' => $wp_version,
		'update_available' => $available,
		'updates_last_checked' => (is_object($updates) && isset($updates->last_checked)) ? (int) $updates->last_checked : null,
	];
}

function plugin_status(): array {
	if (!function_exists('get_plugins')) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	$updates = get_site_transient('update_plugins');
	$responses = (is_object($updates) && isset($updates->response)) ? $updates->response : [];
	$out = [];
	foreach (get_plugins() as $file => $data) {
		$out[] = [
			'file' => $file,
			'name' => $data['Name'],
			'version' => $data['Version'],
			'active' => is_plugin_active($file),
			'update_available' => isset($responses[$file]->new_version) ? $responses[$file]->new_version : null,
		];
	}
	return $out;
}

function theme_status(): array {
	$updates = get_site_transient('update_themes');
	$responses = (is_object($updates) && isset($updates->response)) ? $updates->response : [];
	$active = get_stylesheet();
	$out = [];
	foreach (wp_get_themes() as $slug => $theme) {
		$out[] = [
			'slug' => $slug,
			'name' => $theme->get('Name'),
			'version' => $theme->get('Version'),
			'active' => $slug === $active || $slug === get_template(),
			'update_available' => $responses[$slug]['new_version'] ?? null,
		];
	}
	return $out;
}

// ---------------------------------------------------------------------------
// Status endpoint
// ---------------------------------------------------------------------------

function is_signed_by_scanner(\WP_REST_Request $request): bool {
	$timestamp = (string) $request->get_header('x-ck-health-timestamp');
	$signature = base64_decode((string) $request->get_header('x-ck-health-signature'), true);
	if (!ctype_digit($timestamp) || abs(time() - (int) $timestamp) > MAX_CLOCK_SKEW) {
		return false;
	}
	if ($signature === false || strlen($signature) !== 64 || !function_exists('sodium_crypto_sign_verify_detached')) {
		return false;
	}
	try {
		return sodium_crypto_sign_verify_detached($signature, SIGNED_MESSAGE_PREFIX . $timestamp, base64_decode(SCANNER_PUBLIC_KEY));
	} catch (\Throwable $e) {
		return false;
	}
}

function status_response(): \WP_REST_Response {
	audit_passwords(AUDIT_REQUEST_BUDGET);
	$visitor = resolve_visitor_ip($_SERVER);
	$response = new \WP_REST_Response([
		'plugin_version' => VERSION,
		'wordpress' => wordpress_status(),
		'php' => ['version' => PHP_VERSION],
		'plugins' => plugin_status(),
		'themes' => theme_status(),
		'passwords' => password_audit_summary(),
		'login_limit' => [
			'visitor' => $visitor,
			'active' => $visitor['ip'] !== null,
			'lockouts_by_day' => get_option(LOCKOUTS_OPTION, []),
		],
	]);
	$response->header('Cache-Control', 'no-store, private');
	return $response;
}

add_action('rest_api_init', function () {
	register_rest_route('ck-health/v1', '/status', [
		'methods' => 'GET',
		'callback' => __NAMESPACE__ . '\\status_response',
		'permission_callback' => function (\WP_REST_Request $request) {
			if (is_signed_by_scanner($request)) {
				return true;
			}
			// Look exactly like a site without the plugin.
			return new \WP_Error('rest_no_route', 'No route was found matching the URL and request method.', ['status' => 404]);
		},
	]);
});
