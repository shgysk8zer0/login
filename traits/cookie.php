<?php

namespace shgysk8zer0\Login\Traits;

use \shgysk8zer0\Login\User;

trait Cookie
{
	public static  $expires = '+1 month';
	/**
	 * Sets login cookie, optionally using encryption
	 * @param  String $key        Sets `$_COOKIE[$key]`
	 * @param  String $crypto_pwd Optional password to encrypt with
	 * @return self               Return self to make chainable
	 */
	public function setCookie(String $key = self::KEY, String $crypto_pwd = null): User
	{
		if (is_string($crypto_pwd)) {
			$cookie = static::encrypt(@serialize($this), $crypto_pwd);
		} else {
			$cookie = base64_encode(@serialize($this));
		}
		static::_cookie($key, $cookie, static::$expires);
		return $this;
	}

	/**
	 * Save to session
	 * @param  String $key Sets `$_SESSION[$key]`
	 * @return self        Return self to make chainable
	 */
	public function setSession(String $key = self::KEY): User
	{
		$_SESSION[$key] = @serialize($this);
		return $this;
	}

	/**
	 * Private method for setting cookies more easily
	 * @param  String  $key     Cookie name
	 * @param  String  $value   Value to set it to
	 * @param  Mixed   $expires Expiration timestamp
	 * @return Bool             Whether or not the cookie was set
	 */
	protected static function _cookie(String $key, String $value = null, $expires = 1): Bool
	{
		if (isset($value)) {
			$_COOKIE[$key] = $value;
		} else {
			unset($_COOKIE[$key]);
		}

		return setcookie(
			$key,
			$value,
			is_string($expires) ? strtotime($expires) : $expires,
			'/',
			$_SERVER['HTTP_HOST'],
			array_key_exists('HTTPS', $_SERVER),
			true
		);
	}

	/**
	 * Does timestamp comparision
	 * @param  Mixed   $expires Expiration timestamp or date string
	 * @return Bool             Whether or not it is less than current time
	 */
	protected static function _isExpired($expires): Bool
	{
		if (is_int($expires)) {
			return $expires < time();
		} elseif (is_string($expires)) {
			return strtotime($expires) < time();
		} else {
			return true;
		}
	}
}
