<?php

namespace shgysk8zer0\Login;

use \shgysk8zer0\Core_API as API;

use \shgysk8zer0\Core as Core;

class User implements \jsonSerializable, \Serializable
{
	use WP_Pass;
	use Passwords;

	const MAGIC_PROPERTY = '_user_data';

	const USER_TABLE     = 'users';

	const DATA_TABLE     = 'user_data';

	const KEY            = 'user';

	public $id           = null;

	public $username     = null;

	public $email        = null;

	private $password    = null;

	private $_pdo        = null;

	private $_db_creds   = null;

	private $_user_data  = array();

	private $_tables     = array();

	public static $check_wp_pass = false;

	private static $_instances = array();

	public static  $expires = '+1 month';

	final static public function load($config)
	{
		if (! array_key_exists($config, static::$_instances)) {
			static::$_instances[$config] = new self($config);
		}
		return static::$_instances[$config];
	}

	public function __construct($creds = 'connect.json')
	{
		$this->_db_creds = $creds;
		$this->_pdo = \shgysk8zer0\Core\PDO::load($creds);
	}

	public function __invoke($user, $password)
	{
		$stm = $this->_pdo->prepare($this->_getQuery());
		$stm->bindParam(':user', $user, \PDO::PARAM_STR);
		if ($stm->execute()) {
			$data = $stm->fetch(\PDO::FETCH_ASSOC);

			if (
				array_key_exists('password', $data)
				and ($this->_passwordVerify($password, $data['password']))
			) {
				$this->_setData($data);
				return true;
			} elseif (
				array_key_exists('password', $data) and static::$check_wp_pass === true
				and ($this->_passwordVerify($password, $data['password']))
			) {
				$hash = $this->_passwordHash($password);
				$update = $pdo->prepare("UPDATE `users` SET `password` = :hash WHERE `username` = :user LIMIT 1;");
				$update->bindParam(':hash', $hash);
				$update->bindParam(':user', $data['username']);
				if ($update->execute()) {
					$data['password'] = $hash;
					$this->_setData($data);
					return true;
				} else {
					trigger_error('Error updating password');
					return false;
				}
			} else {
				return false;
			}
		}
		return false;
	}

	public function __get($prop)
	{
		if ($this->__isset($prop)) {
			return $this->{self::MAGIC_PROPERTY}[$prop];
		} else {
			trigger_error("Attempting to get unknown property: '$prop'.");
		}
	}

	public function __isset($prop)
	{
		return array_key_exists($prop, $this->{self::MAGIC_PROPERTY});
	}

	public function __toString()
	{
		return $this->username;
	}

	public function __debugInfo()
	{
		return $this->_getData();
	}

	public function jsonSerialize()
	{
		return $this->_getData();
	}

	public function serialize()
	{
		$expires = strtotime(static::$expires);
		$data = [
			'username' => $this->username,
			'tables'   => $this->_tables,
			'db_creds' => $this->_db_creds,
			'expires'  => $expires,
		];
		return serialize($data);
	}

	public function unserialize($data)
	{
		$data = unserialize($data);
		$data = new \ArrayObject($data, \ArrayObject::ARRAY_AS_PROPS);
		if (isset($data->username, $data->expires, $data->db_creds, $data->tables)) {
			static::$expires = $data->expires;
			unset($data->expires);
			$this->_db_creds = $data->db_creds;
			$this->_pdo = Core\PDO::load($this->_db_creds);
			$this->_tables = $data->tables;

			$stm = $this->_pdo->prepare($this->_getQuery());
			$stm->bindParam(':user', $data->username, \PDO::PARAM_STR);
			if ($stm->execute()) {
				$data = $stm->fetch(\PDO::FETCH_ASSOC);
				$this->_setData($data);
			}
			static::$_instances[$this->_db_creds] = $this;
		}
	}

	public function setCookie($key = self::KEY)
	{
		$cookie = base64_encode(serialize($this));
		return setcookie(
			$key,
			$cookie,
			strtotime($this::$expires),
			'/',
			$_SERVER['HTTP_HOST'],
			array_key_exists('HTTPS', $_SERVER),
			true
		);
	}

	public function setSession($key = self::KEY)
	{
		$_SESSION[$key] = @serialize($this);
	}

	public function logout($key = self::KEY)
	{
		if (array_key_exists($key, $_COOKIE)) {
			setcookie($key, null, 1);
		}
		unset($_COOKIE[$key], $_SESSION[$key]);
		$this->id = null;
		$this->username = null;
		$this->password = null;
		$this->_user_data = array();
		return $this;
	}

	public function hasTable($table)
	{
		return in_array($table, $this->_tables);
	}

	public function getTables()
	{
		return array_map(function($table)
		{
			return sprintf('`%s`', preg_replace('/[^\w\- ]/', null, $table));
		}, $this->_tables);
	}

	public function addTable($table)
	{
		if (! $this->hasTable($table)) {
			array_push($this->_tables, $table);
			return true;
		} else {
			return false;
		}
	}

	public static function restore($key = self::KEY, $db_creds = null)
	{
		if (is_null($db_creds)) {
			trigger_error(sprintf('No db creds given in %s', __METHOD__));
		}
		if (array_key_exists($db_creds, static::$_instances)) {
			return static::$_instances[$db_creds];
		}
		if (array_key_exists($key, $_COOKIE)) {
			$_SESSION[$key] = @base64_decode($_COOKIE[$key]);
			$user = @unserialize($_SESSION[$key]);
		} elseif (array_key_exists($key, $_SESSION)) {
			$user = @unserialize($_SESSION[$key]);
		} else {
			$user = new self($db_creds);
			if (
				array_key_exists('PHP_AUTH_USER', $_SERVER)
				and array_key_exists('PHP_AUTH_PW', $_SERVER)
			) {
				$user($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
			}
		}

		if (is_null($user) or static::_isExpired($user::$expires)) {
			if (array_key_exists($key, $_COOKIE)) {
				setcookie($key, null, 1);
				unset($_COOKIE[$key]);
			}
			if (array_key_exists($key, $_SESSION)) {
				unset($_SESSION[$key]);
			}
			$user = new self($db_creds);
		}
		static::$_instances[$db_creds] = $user;
		return $user;
	}

	private static function _isExpired($time)
	{
		$now = new \DateTime('now');
		if (strval(@intval($time)) == $time) {
			return new \DateTime("@{$time}") < $now;
		} elseif (is_string($time)) {
			return new \DateTime($time) < $now;
		} else {
			return true;
		}
	}

	private function _getData()
	{
		return array_merge([
			'id' => $this->id,
			'username' => $this->username,
			'email' => $this->email,
		], $this->{self::MAGIC_PROPERTY});
	}

	private function _setData(Array $data)
	{
		$this->id       = $data['id'];
		$this->username = $data['username'];
		$this->email    = $data['email'];
		$this->password = $data['password'];
		unset($data['id']);
		unset($data['username']);
		unset($data['email']);
		unset($data['password']);
		$this->{self::MAGIC_PROPERTY} = $data;
	}

	private function _getQuery()
	{
		return 'SELECT * FROM `users`
			JOIN(`user_data`, `subscribers`)
			ON (`user_data`.`id` = `users`.`id` AND `subscribers`.`id` = `users`.`id`)
			WHERE `users`.`email` = :user OR `users`.`username` = :user
			LIMIT 1;';
	}
}
