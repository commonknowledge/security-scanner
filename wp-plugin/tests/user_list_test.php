<?php
// Run: php wp-plugin/tests/user_list_test.php
namespace {
	define('ABSPATH', __DIR__);
	function add_action() {}
	function add_filter() {}
	$GLOBALS['logged_in'] = false;
	function is_user_logged_in() { return $GLOBALS['logged_in']; }
	function rest_authorization_required_code() { return $GLOBALS['logged_in'] ? 403 : 401; }
	class WP_Error {
		public $code, $data;
		function __construct($code, $message, $data) { $this->code = $code; $this->data = $data; }
	}
	class FakeRequest {
		private $route;
		function __construct($route) { $this->route = $route; }
		function get_route() { return $this->route; }
	}
	require __DIR__ . '/../ck-health/health.php';
}

namespace Tests {
	use function CommonKnowledge\Health\protect_user_list;

	$failed = 0;
	$check = function ($name, $ok) use (&$failed) {
		echo ($ok ? 'ok   ' : 'FAIL ') . $name . "\n";
		$failed += $ok ? 0 : 1;
	};
	$blocked = function ($route, $result = null) {
		$out = protect_user_list($result, null, new \FakeRequest($route));
		return $out instanceof \WP_Error && $out->code === 'rest_user_cannot_view' && $out->data['status'] === 401;
	};

	$GLOBALS['logged_in'] = false;
	$check('visitor: user list refused', $blocked('/wp/v2/users'));
	$check('visitor: single user refused', $blocked('/wp/v2/users/1'));
	$check('visitor: users/me refused', $blocked('/wp/v2/users/me'));
	$check('visitor: posts still allowed', protect_user_list(null, null, new \FakeRequest('/wp/v2/posts')) === null);
	$check('visitor: similar route not caught', protect_user_list(null, null, new \FakeRequest('/wp/v2/usersettings')) === null);
	$check('visitor: CK Health status untouched', protect_user_list(null, null, new \FakeRequest('/ck-health/v1/status')) === null);
	$check('earlier result passed through', protect_user_list('cached', null, new \FakeRequest('/wp/v2/users')) === 'cached');

	$GLOBALS['logged_in'] = true;
	$check('logged in: user list allowed', protect_user_list(null, null, new \FakeRequest('/wp/v2/users')) === null);

	exit($failed ? 1 : 0);
}
