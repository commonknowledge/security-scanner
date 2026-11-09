<?php
/**
 * Plugin Name: CK Health
 * Plugin URI: https://github.com/commonknowledge/security-scanner
 * Description: Lets the Common Knowledge security scanner check this site's WordPress and PHP versions and find accounts with easily guessed passwords. Also slows down password guessing on the login form.
 * Version: 0.2.0
 * Requires PHP: 7.2
 * Author: Common Knowledge
 * License: GPL-2.0-or-later
 * Update URI: https://github.com/commonknowledge/security-scanner
 *
 * Install the zip from the latest GitHub release. Updates then arrive like any other
 * plugin's. No configuration needed.
 *
 * This file uses only old PHP syntax, so a site on an ancient PHP version doesn't crash.
 * The checks need PHP 7.2; updates need PHP 7.4. On older versions the scanner gets no
 * answer, or sees an old plugin version, and reports the site.
 */

if (!defined('ABSPATH')) {
	exit;
}

if (version_compare(PHP_VERSION, '7.2', '<')) {
	return;
}

define('CK_HEALTH_FILE', __FILE__);
require __DIR__ . '/health.php';

// Updates come from this repo's GitHub releases. The "Update URI" header above stops
// WordPress.org from ever offering an unrelated plugin that happens to share our slug.
if (version_compare(PHP_VERSION, '7.4', '>=') && file_exists(__DIR__ . '/vendor/autoload.php')) {
	require __DIR__ . '/vendor/autoload.php';
	$ck_health_updates = \YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
		'https://github.com/commonknowledge/security-scanner/',
		__FILE__,
		'ck-health'
	);
	$ck_health_updates->getVcsApi()->enableReleaseAssets('/ck-health\.zip($|[?&#])/i');
}
