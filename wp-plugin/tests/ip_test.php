<?php
// Run: php wp-plugin/tests/ip_test.php
define('ABSPATH', __DIR__);
function add_action() {}
function add_filter() {}
require __DIR__ . '/../ck-health/health.php';

use function CommonKnowledge\Health\resolve_visitor_ip;

$cases = [
	'direct connection' =>
		[['REMOTE_ADDR' => '203.0.113.7'], '203.0.113.7', 'direct'],
	'direct connection ignores forged headers' =>
		[['REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1', 'HTTP_CF_CONNECTING_IP' => '1.1.1.1'], '203.0.113.7', 'direct'],
	'cloudflare edge' =>
		[['REMOTE_ADDR' => '172.70.1.2', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7'], '203.0.113.7', 'cloudflare'],
	'cloudflare edge without header' =>
		[['REMOTE_ADDR' => '172.70.1.2'], null, 'unresolved'],
	'host load balancer' =>
		[['REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'], '203.0.113.7', 'proxy'],
	'host load balancer, forged left entries ignored' =>
		[['REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.7'], '203.0.113.7', 'proxy'],
	'host load balancer, internal hops skipped' =>
		[['REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7, 10.9.9.9, 100.64.0.1'], '203.0.113.7', 'proxy'],
	'cloudflare in front of host load balancer' =>
		[['REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.7, 162.158.1.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7'], '203.0.113.7', 'proxy+cloudflare'],
	'load balancer with no header' =>
		[['REMOTE_ADDR' => '10.1.2.3'], null, 'unresolved'],
	'load balancer with garbage hop' =>
		[['REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7, unknown'], null, 'unresolved'],
	'port on forwarded IPv4' =>
		[['REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7:51234'], '203.0.113.7', 'proxy'],
	'IPv6 direct' =>
		[['REMOTE_ADDR' => '2001:db8::1'], '2001:db8::1', 'direct'],
	'IPv6 cloudflare' =>
		[['REMOTE_ADDR' => '2606:4700:10::1', 'HTTP_CF_CONNECTING_IP' => '2001:db8::1'], '2001:db8::1', 'cloudflare'],
	'IPv4-mapped IPv6 load balancer' =>
		[['REMOTE_ADDR' => '::ffff:10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'], '203.0.113.7', 'proxy'],
	'localhost' =>
		[['REMOTE_ADDR' => '127.0.0.1'], null, 'unresolved'],
	'missing REMOTE_ADDR' =>
		[[], null, 'unresolved'],
];

$failed = 0;
foreach ($cases as $name => [$server, $ip, $via]) {
	$got = resolve_visitor_ip($server);
	$ok = $got['ip'] === $ip && $got['via'] === $via;
	$failed += $ok ? 0 : 1;
	printf("%s %s%s\n", $ok ? 'ok  ' : 'FAIL', $name, $ok ? '' : sprintf(' (got %s via %s)', var_export($got['ip'], true), $got['via']));
}
exit($failed ? 1 : 0);
