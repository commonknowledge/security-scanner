<?php
/**
 * Plugin Name: CK Health
 * Description: Lets the Common Knowledge scanner check this site's WordPress and PHP versions and find accounts with easily guessed passwords. Also slows down password guessing on the login form.
 * Version: 0.1.0
 * Author: Common Knowledge
 * License: GPL-2.0-or-later
 *
 * Must-use plugin. Install by copying this file and the ck-health/ folder into
 * wp-content/mu-plugins/. No configuration needed.
 *
 * This loader uses only old PHP syntax, so a site on an ancient PHP version doesn't
 * crash. On PHP older than 7.2 the plugin stays off, the scanner gets no answer, and
 * the site is reported as needing attention.
 */

if (!defined('ABSPATH')) {
	exit;
}

if (version_compare(PHP_VERSION, '7.2', '>=')) {
	require __DIR__ . '/ck-health/health.php';
}
